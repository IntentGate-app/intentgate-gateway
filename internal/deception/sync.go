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
// so the Detector neither knows nor cares where decoys come from. The active
// set is swapped atomically; a failed refresh keeps the last-known-good set,
// so a console blip never opens a detection gap.
type SyncRegistry struct {
	reg atomic.Pointer[StaticRegistry]
}

// NewSyncRegistry seeds the registry, typically with the config-file set, so
// the gateway is armed from the first request, before the first poll returns.
func NewSyncRegistry(seed []Decoy) *SyncRegistry {
	s := &SyncRegistry{}
	s.reg.Store(NewStaticRegistry(seed))
	return s
}

// Match implements Registry by delegating to the current decoy set.
func (s *SyncRegistry) Match(in Input) (Decoy, bool) {
	return s.reg.Load().Match(in)
}

// set atomically replaces the live decoy set.
func (s *SyncRegistry) set(decoys []Decoy) {
	s.reg.Store(NewStaticRegistry(decoys))
}

// FetchDecoys pulls the active decoy set from the console export endpoint
// (GET, bearer-authenticated). The response shape is
// {"decoys":[{"id","name","kind","key","pillar","on_trip","synthetic"}]}.
// "synthetic" carries the fake payload a sandbox decoy serves; it
// deserializes into Decoy.Synthetic and is empty for tripwire decoys.
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
// and onErr is called; on success onOK is called with the decoy count. Both
// callbacks may be nil.
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
