package sessionrewind

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
)

// Replay prevention. After a call is blocked and the agent is rewound, a
// confused agent often re-emits the exact same call. Without a guard that
// means another full LLM round-trip and another policy evaluation for a
// decision the gateway already made. The ReplayGuard fingerprints blocked
// payloads per session so an identical retry is short-circuited instantly,
// with the same recovery envelope, without a fresh model call.

// FingerprintArgs returns a stable fingerprint for a (session, tool, args)
// call. json.Marshal sorts map keys, so argument order does not change the
// fingerprint and a semantically identical retry matches.
func FingerprintArgs(sessionID, tool string, args map[string]any) string {
	b, _ := json.Marshal(args)
	sum := sha256.Sum256([]byte(sessionID + "|" + tool + "|" + string(b)))
	return hex.EncodeToString(sum[:])
}

// ReplayGuard remembers the fingerprints of calls that were blocked, so an
// identical retry can be refused without re-evaluating or re-prompting the
// model. It is per-process and safe for concurrent use; a shared deployment
// would back the same two methods with Redis.
type ReplayGuard struct {
	mu      sync.RWMutex
	blocked map[string]struct{}
}

// NewReplayGuard returns an empty guard.
func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{blocked: make(map[string]struct{})}
}

// Block records that a fingerprint was refused.
func (g *ReplayGuard) Block(fp string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blocked[fp] = struct{}{}
}

// IsBlocked reports whether this exact call has already been refused, so the
// caller can short-circuit it instantly.
func (g *ReplayGuard) IsBlocked(fp string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	_, ok := g.blocked[fp]
	return ok
}

// Clear forgets a fingerprint, for when an operator explicitly re-authorizes
// an action that was previously blocked.
func (g *ReplayGuard) Clear(fp string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.blocked, fp)
}
