# IntentGate Deception — Operations & Wiring Manual

Audience: engineers standing up and running the deception fabric.
Scope: how the console Deception page and the gateway detector fit together,
what is wired today, the one change needed to make "activate in the console"
arm the gateway automatically, and the day-to-day operator steps.

---

## 0. The one thing to understand first

Deception has two halves that talk over two HTTP calls:

- **Console (`console-pro`)** is the *design and governance* surface. You
  deploy playbooks, approve decoys, activate/retire them, and read trips with
  forensics and evidence export. It owns the decoy records in Postgres.
- **Gateway** is the *inline detector*. On every tool call it checks whether
  the call touched a decoy and, if so, contains it (kill switch + token
  revoke) and records the trip.

The seam between them is two endpoints:

| Direction | Endpoint | Auth | Purpose |
|---|---|---|---|
| gateway → console | `POST /api/deception/trip` | `Bearer INTENTGATE_DECEPTION_TOKEN` | gateway reports a live trip; console records it in the Monitor tab |
| console → gateway | `GET /api/deception/decoys` | `Bearer INTENTGATE_DECEPTION_TOKEN` | gateway pulls the **active** decoy set to arm its detector |

**What is wired today:** the trip direction (gateway → console) is live — you
saw it in the startup log (`deception trip mirroring enabled`). The decoy
direction is only half-built: the console *serves* `GET /api/deception/decoys`
(active decoys only), but the gateway does **not yet consume it**. The gateway
arms itself from the static JSON file at `INTENTGATE_DECEPTION_CONFIG_PATH`
(the four lab decoys). So **activating a decoy in the console does not arm the
gateway yet** — that is the gap this manual closes in Section 3.

Two ways to run, depending on whether you want to ship the gateway change:

- **Section 2 — static set (works today, no code):** the file is the armed
  set; the console is used for governance + monitoring of that set.
- **Section 3 — live sync (the real integration, ~1 small gateway file):** the
  gateway polls `GET /api/deception/decoys`, so "activate in the console"
  arms the gateway within one poll interval. This is the target.

---

## 1. Data model and match semantics (so the two halves agree)

A **decoy** is an asset no legitimate agent should ever touch. The gateway
matches a call against decoys by *kind*:

| Kind | What the gateway matches on | `key` the console exports |
|---|---|---|
| `honey_tool` | the tool name being called | decoy name |
| `decoy_token` | the capability-token id (jti) presented | decoy id |
| `decoy_zone` | the zone/service being reached | decoy name |
| `honey_credential` | a brokered credential id, or the value seen in call args | decoy name |
| `honey_record` | a seeded value (payee id, record key) seen in call args | decoy name |

The console's export (`app/api/deception/decoys/route.ts`) already produces
exactly this shape and picks `key` correctly (`decoy_token` → id, everything
else → name). The gateway's `deception.Decoy` struct
(`internal/deception/deception.go`) is the mirror of that JSON. **They already
line up** — the only missing piece is the gateway fetching it.

`on_trip` drives the response: `contain` → kill switch + token revoke
(critical), `hold` → pause for a responder (high), `alert` → flag only
(medium).

---

## 2. Put it to work TODAY — static decoy set (no code change)

Use this to run deception now. The gateway's armed set is the JSON file; the
console governs and monitors it.

1. **Author the decoy set** as JSON (this is the lab file, `lab/deception-decoys.json`):

   ```json
   {
     "decoys": [
       { "id": "d1", "name": "admin_payments",      "kind": "honey_tool",       "key": "admin_payments",      "pillar": "tool",     "on_trip": "contain" },
       { "id": "d2", "name": "export_all_customers", "kind": "honey_tool",       "key": "export_all_customers", "pillar": "data",     "on_trip": "contain" },
       { "id": "d3", "name": "ACME-SHELL-LTD",       "kind": "honey_record",     "key": "ACME-SHELL-LTD",       "pillar": "data",     "on_trip": "hold" },
       { "id": "d4", "name": "AKIA-LAB-DECOY-9",     "kind": "honey_credential", "key": "AKIA-LAB-DECOY-9",     "pillar": "identity", "on_trip": "contain" }
     ]
   }
   ```

2. **Mount it and point the gateway at it** (already set in `lab/compose.yml`):

   ```yaml
   gateway:
     environment:
       INTENTGATE_DECEPTION_CONFIG_PATH: "/etc/intentgate/deception-decoys.json"
       INTENTGATE_DECEPTION_TOKEN: "${INTENTGATE_DECEPTION_TOKEN:-lab-deception-token}"
       INTENTGATE_DECEPTION_TRIP_URL: "http://console-pro:3000/api/deception/trip"
     volumes:
       - ./deception-decoys.json:/etc/intentgate/deception-decoys.json:ro
   ```

3. **Restart the gateway** and confirm it armed:

   ```
   docker compose --profile deploy up -d gateway
   docker compose logs gateway | grep -i deception
   # expect: deception enabled ... decoys=4
   ```

4. **Verify a trip end to end** — call one of the honey tools through the
   gateway (e.g. `admin_payments`). The gateway contains it and POSTs to the
   console; it appears on the **Monitor** tab.

Limitation of this mode: decoys you deploy/activate in the console UI are
recorded but not armed. To change the armed set you edit the file and restart.
Section 3 removes that limitation.

---

## 3. Put it to work PROPERLY — live sync (make the page arm the gateway)

Goal: when an operator activates a decoy in the console, the gateway picks it
up automatically. The console endpoint already exists; we add a fetch loop on
the gateway that swaps the decoy set behind the existing `Registry` seam. No
change to the detection hot path, no change to the console.

### 3.1 Add `internal/deception/sync.go`

```go
package deception

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// SyncRegistry is a Registry whose decoy set is refreshed from the console
// decoy store over HTTP. It satisfies the same Match seam as StaticRegistry,
// so the Detector neither knows nor cares where decoys come from. The set is
// swapped atomically; a failed refresh keeps the last-known-good set, so a
// console blip never opens a detection gap.
type SyncRegistry struct {
	reg atomic.Pointer[StaticRegistry]
}

// NewSyncRegistry seeds the registry (typically with the config-file set) so
// the gateway is armed from the first request, before the first poll returns.
func NewSyncRegistry(seed []Decoy) *SyncRegistry {
	s := &SyncRegistry{}
	s.reg.Store(NewStaticRegistry(seed))
	return s
}

func (s *SyncRegistry) Match(in Input) (Decoy, bool) { return s.reg.Load().Match(in) }

func (s *SyncRegistry) set(decoys []Decoy) { s.reg.Store(NewStaticRegistry(decoys)) }

// FetchDecoys pulls the active decoy set from the console export endpoint.
func FetchDecoys(ctx context.Context, client *http.Client, url, token string) ([]Decoy, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("deception sync: status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		Decoys []Decoy `json:"decoys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Decoys, nil
}

// RunSync refreshes the registry from url every interval until ctx is done.
// The first refresh runs immediately. On error the previous set is retained
// and onErr is called; on success onOK is called with the decoy count.
func (s *SyncRegistry) RunSync(
	ctx context.Context, client *http.Client, url, token string,
	interval time.Duration, onOK func(int), onErr func(error),
) {
	refresh := func() {
		decoys, err := FetchDecoys(ctx, client, url, token)
		if err != nil {
			if onErr != nil {
				onErr(err)
			}
			return
		}
		s.set(decoys)
		if onOK != nil {
			onOK(len(decoys))
		}
	}
	refresh()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refresh()
		}
	}
}
```

### 3.2 Wire it in `cmd/gateway/main.go`

Right after the existing static-file block (the one that logs `deception
enabled`), add a sync path. Keep the file set as the bootstrap seed so there
is never an unarmed window and so the gateway still works if the console is
briefly unreachable at boot.

```go
// Live sync: if a console decoy endpoint is set, poll it and hot-swap the
// decoy set. Seeded with the file set (may be nil) so we are armed from the
// first request. watchCtx already exists in main() for the other reloaders.
if syncURL := os.Getenv("INTENTGATE_DECEPTION_SYNC_URL"); syncURL != "" {
	sr := deception.NewSyncRegistry(decoys) // decoys = the file set from the block above
	deceptionDetector = deception.New(sr)

	interval := 15 * time.Second
	if v := os.Getenv("INTENTGATE_DECEPTION_SYNC_INTERVAL_S"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			interval = time.Duration(n) * time.Second
		}
	}
	token := os.Getenv("INTENTGATE_DECEPTION_TOKEN")
	go sr.RunSync(watchCtx, http.DefaultClient, syncURL, token, interval,
		func(n int) { logger.Info("deception decoys synced from console", "url", syncURL, "decoys", n) },
		func(err error) { logger.Warn("deception decoy sync failed; keeping last-known-good set", "err", err) },
	)
	logger.Info("deception live sync enabled", "url", syncURL, "interval_s", int(interval/time.Second))
}
```

Notes:
- `decoys` and `deceptionDetector` are already in scope from the static block.
- `watchCtx` is the long-lived context main() already uses for the policy and
  credential reloaders — reuse it so the goroutine stops on shutdown.
- `net/http` and `strconv` are already imported.
- Fail-safe by design: a fetch error logs and keeps the previous set; the
  detector never falls open.

### 3.3 Tests (`internal/deception/sync_test.go`)

Cover the three things that matter:
1. `FetchDecoys` parses the console shape (spin up an `httptest.Server`
   returning `{"decoys":[...]}` and assert the parsed slice).
2. `SyncRegistry.Match` returns the newly-set decoys after `set(...)`.
3. On a non-200 / transport error, `RunSync` keeps the seed set (Match still
   hits the seed decoy). Use a server that 500s and assert last-known-good.

### 3.4 Turn it on in the lab (`lab/compose.yml`)

Add to the `gateway` service environment (the token and trip URL are already
there):

```yaml
      INTENTGATE_DECEPTION_SYNC_URL: "http://console-pro:3000/api/deception/decoys"
      INTENTGATE_DECEPTION_SYNC_INTERVAL_S: "15"
```

You can keep `INTENTGATE_DECEPTION_CONFIG_PATH` as the bootstrap seed or drop
it once the console holds the real set. Rebuild:

```
docker compose --profile deploy up -d --build gateway
docker compose logs gateway | grep -i deception
# expect: deception live sync enabled ... then: deception decoys synced from console ... decoys=N
```

Now activate a decoy in the console and within 15s the gateway arms it — no
restart, no file edit.

---

## 4. Operator run-book — using the page day to day

Once armed (Section 2 or 3), this is the loop an operator runs on the page.

1. **Deploy** — *Playbooks* tab. Pick the playbook matching the threat
   (payment abuse, data exfil, privilege escalation, injection follower,
   runaway mass action, lateral movement). In "Place on" name the agent or
   zone you are baiting. Click **Deploy**. The playbook's decoys are created
   as **staged**.

2. **Approve** — *Decoys* tab. Staged decoys need approval. Separation of
   duties applies: the person who deployed a decoy cannot approve it, unless
   `INTENTGATE_DECEPTION_ALLOW_SELF_APPROVE=true` (set on the lab for
   single-operator demos). Approve moves it to **approved**.

3. **Activate** — *Decoys* tab. Flip approved decoys to **active**. Only
   active decoys are exported to the gateway (Section 3) / belong in the armed
   file (Section 2). The `active / staged / trips` counters update.

4. **Monitor** — *Monitor* tab. When an agent touches an active decoy a
   **trip** is recorded: agent, severity, the forensic timeline, and the
   containment taken. A contained trip also raises that agent's risk tier in
   the inventory. Review/close trips and **Export evidence (CSV)** for the
   incident record.

5. **Simulate** (demo/verification) — *Monitor* tab has **Simulate trip**,
   which exercises the detect → contain → record loop against the first active
   decoy without needing real hostile traffic. Use it to prove the page works.

6. **Retire / mute** — *Decoys* tab, when a decoy has served its purpose or is
   noisy. Retired decoys stop being exported/armed.

---

## 5. Gotcha: placement is advisory today

The console "Place on (agent or zone)" field is recorded on the decoy but the
gateway currently matches **globally** — any call touching a decoy's key trips
it, regardless of which agent the operator named. That is correct and safe (a
decoy is a decoy for everyone), but it means "place on Payments agent" is
documentation, not a scoping rule. If you want per-agent/zone scoping (a decoy
that only trips for a specific caller), that is a follow-up: carry the
placement into the export, add it to `deception.Decoy` + `Input`, and gate the
match on it. Not required for v1; note it so nobody assumes scoping exists.

---

## 6. Config reference

Gateway:

| Env | Meaning |
|---|---|
| `INTENTGATE_DECEPTION_CONFIG_PATH` | static decoy JSON file; bootstrap/seed set |
| `INTENTGATE_DECEPTION_SYNC_URL` | console decoy export URL (`.../api/deception/decoys`) — enables live sync |
| `INTENTGATE_DECEPTION_SYNC_INTERVAL_S` | poll interval, default 15 |
| `INTENTGATE_DECEPTION_TRIP_URL` | console trip-ingest URL (`.../api/deception/trip`) |
| `INTENTGATE_DECEPTION_TOKEN` | shared bearer for both endpoints |

Console (`console-pro`):

| Env | Meaning |
|---|---|
| `INTENTGATE_DECEPTION_TOKEN` | must match the gateway's token (guards both endpoints) |
| `INTENTGATE_DECEPTION_ALLOW_SELF_APPROVE` | `true` lets the deployer approve their own decoy (single-operator demos only) |

Endpoints (both `Bearer INTENTGATE_DECEPTION_TOKEN`):
- `GET  /api/deception/decoys` → `{ decoys: [ { id, name, kind, key, pillar, on_trip } ] }` (active only)
- `POST /api/deception/trip` → records a trip in the Monitor tab

---

## 7. Verification checklist

- [ ] Gateway logs `deception enabled` (static) or `deception live sync enabled` + `deception decoys synced from console` (sync).
- [ ] Console → Deception page loads for an **admin** user; Gateway shows **connected**.
- [ ] Deploy a playbook → decoys appear **staged** on the Decoys tab.
- [ ] Approve + activate → `active` counter increments.
- [ ] (Sync mode) within one interval, gateway logs `decoys synced ... decoys=N` with N matching the active count.
- [ ] Simulate trip → a trip with a forensic timeline appears on Monitor; Export evidence downloads a CSV.
- [ ] Real touch: call a honey tool through the gateway → contained + trip recorded + agent risk tier raised.
