# Per-tool fault isolation (AGENT08)

The fault-isolation layer closes OWASP Agentic AGENT08 (Cascading
Failures) at the gateway: one slow or failing tool cannot starve
healthy tools or cascade into agent-wide degradation. Two mechanisms,
both per-tool: a circuit breaker and a bulkhead semaphore.

## What threat does this close?

A single tool starts misbehaving — the vector store returns 500s, a
database is locking up, an LLM provider is rate-limiting. Every call
to that tool hangs. Today, the gateway's goroutines and the upstream
client's connection pool drain into that one tool. Healthy tools
inherit the slow tool's latency: their calls queue behind the failed
ones, eventually time out, and the agent layer degrades together.

Per-tool fault isolation contains the blast radius to the failing
tool only.

## What the two mechanisms do

### Bulkhead (per-tool semaphore)

A capacity of N for tool X means at most N concurrent forwards to X.
Excess callers fail-fast with `ErrBulkheadFull`. A misbehaving tool
can fill its own slots but cannot consume slots that belong to other
tools. Tool A's bulkhead at 100% utilisation has zero effect on
tool B's capacity.

### Circuit breaker (per-tool state machine)

```
        closed  ── N consecutive failures ──▶  open
          ▲                                     │
          │                       cooldown ms expires
          │                                     │
          │                                     ▼
          ╰──── probe succeeds ──── half_open ◀─╯
                                       │
                                  probe fails
                                       │
                                       ▼
                                     open
                                  (cooldown reset)
```

- **Closed**: calls pass through. Consecutive failures accumulate.
- **Open**: calls fail-fast with `ErrCircuitOpen` for the cooldown
  window. The upstream is not contacted.
- **Half-open**: exactly one probe is allowed through. Success closes
  the breaker; failure re-opens it and resets the cooldown.

Both mechanisms are completely per-tool. State for tool A is in a
separate `sync.Map` entry from tool B. A breaker open on tool A has
no effect on tool B at all.

## Where it sits in the pipeline

The gate runs inside `forwardToUpstream`, immediately before the
actual upstream HTTP call:

```
... → all auth checks passed → Acquire(tool) → upstream.Forward(body) → release(outcome)
```

When the gate returns `nil, err`, the gateway never contacts the
upstream — the agent gets `-32018 upstream temporarily unavailable`
with a structured reason (`circuit_open` or `bulkhead_full`).

When the forward returns, the gate's `release` callback records the
outcome (success / failure) so the breaker's counter is accurate.

## What counts as a failure

The breaker is for **upstream health**, not for application errors:

- Transport error from the upstream client → failure
- HTTP `>= 500` → failure
- HTTP `< 500` (including 4xx) → success
- JSON-RPC error in the response body (e.g. tool says "db unavailable"
  with a 200 OK envelope) → success

This is deliberate. If the upstream is healthy enough to answer with
a structured error, the breaker has no business opening. Operators
who want to break on specific application errors can layer that into
Rego.

## Configuration

```
INTENTGATE_FAULT_ISOLATION_ENABLED=true
INTENTGATE_FAULT_ISOLATION_MAX_CONCURRENT_PER_TOOL=20    # bulkhead size
INTENTGATE_FAULT_ISOLATION_FAILURE_THRESHOLD=5           # consec failures to trip
INTENTGATE_FAULT_ISOLATION_COOLDOWN_MS=30000             # open-state duration
```

When `_ENABLED=false` (default), the layer is a no-op closure and
every call passes through. The tunables only matter when the layer
is enabled.

Setting `MAX_CONCURRENT_PER_TOOL=0` disables the bulkhead while
leaving the breaker running. Setting `FAILURE_THRESHOLD=0` disables
the breaker while leaving the bulkhead running. Most deployments
want both.

## What the audit chain stores

Only refused calls produce an audit row from this stage:

- `check = fault_isolation`
- `decision = block`
- `reason = upstream forward refused: circuit_open` or `bulkhead_full`

Healthy calls do not emit a row from this stage — the downstream
`upstream` check is already recording every forward.

## State is per-process

The breaker / bulkhead state lives in-process. In a multi-replica
deployment each replica maintains its own state. That's the standard
shape for circuit-breaker patterns: the failure surface is
per-replica anyway (an upstream that times out from host X might
still be reachable from host Y; closing X's breaker doesn't tell us
anything useful about Y).

For coordinated tripping across replicas — useful for very large
fleets — operators can run the gateway behind a service mesh that
emits its own breaker telemetry and act on that signal. The
gateway's per-replica breaker stays as the fast-path local check.

## How the check is wired

```go
var release func(faultisolation.Outcome)
if h.cfg.FaultIsolation != nil {
    var fiErr error
    release, fiErr = h.cfg.FaultIsolation.Acquire(ctx, params.Name)
    if fiErr != nil {
        // -32018
    }
}
upResp, err := h.cfg.Upstream.Forward(ctx, body)
if release != nil {
    switch {
    case err != nil:
        release(faultisolation.OutcomeFailure)
    case upResp != nil && upResp.Status >= 500:
        release(faultisolation.OutcomeFailure)
    default:
        release(faultisolation.OutcomeSuccess)
    }
}
```

The full source is in `internal/faultisolation/`. The concurrency
stress test (`TestBulkhead_ConcurrentStress`) runs 100 goroutines
against a capacity-5 bulkhead for 50 iterations each and verifies
the in-flight count never exceeds 5. The breaker tests use an
overridable clock to deterministically exercise the closed / open /
half-open transitions.
