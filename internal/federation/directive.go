package federation

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// The DOWN half of the split plane: a directive the control plane hands to a
// node so a global "STOP ALL AGENTS" (or a per-domain stop) can be broadcast
// from one console across every environment at once. The node polls for its
// directive over the same outbound-only path it uses to push telemetry -- the
// control plane never dials in. When a directive says stop, the node engages
// its LOCAL kill switch; when it clears, the node releases the kill it set.
//
// A directive is bound to a single node id and HMAC-signed with that node's
// federation signing key, so a directive cannot be replayed to a different node
// and a man-in-the-middle cannot forge a stop -- or, more dangerously, forge a
// release. When the node has a signing key configured, an unsigned or
// mis-signed directive is ignored; the node fails safe and keeps its current
// state rather than acting on an unverified command.

// DirectiveVersion is the schema version of the directive body.
const DirectiveVersion = "fed-directive-1"

// DirectiveKeyID identifies the signing key used for directives.
const DirectiveKeyID = "federation-directive-v1"

// Directive is the control-plane command a node polls for. It is per-node
// (resolved from the node's global and domain directives) so the signature can
// bind it to exactly this node.
type Directive struct {
	Version   string `json:"version"`
	NodeID    string `json:"node_id"`
	Stop      bool   `json:"stop"`   // true: engage local kill switch (global scope)
	Scope     string `json:"scope"`  // "global" | a domain name | "" when not stopped
	Reason    string `json:"reason"` // operator-supplied reason, for the local audit
	Seq       int64  `json:"seq"`    // monotonic; lets a node tell a directive changed
	IssuedAt  string `json:"issued_at"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature,omitempty"`
}

// DirectiveCanonicalString is the deterministic signing form, matched byte for
// byte by the control-plane (TypeScript) signer. Fixed field order; the stop
// flag is emitted as 1/0 so both languages agree.
func DirectiveCanonicalString(d Directive) string {
	stop := "0"
	if d.Stop {
		stop = "1"
	}
	return strings.Join([]string{
		"fed-directive-canonical-v1",
		d.Version,
		d.NodeID,
		stop,
		d.Scope,
		strconv.FormatInt(d.Seq, 10),
		d.IssuedAt,
		d.Reason,
	}, "\n")
}

// SignDirective stamps the key id and HMAC-SHA256 signs the directive.
func SignDirective(d *Directive, keyID string, key []byte) error {
	d.KeyID = keyID
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(DirectiveCanonicalString(*d)))
	d.Signature = hex.EncodeToString(mac.Sum(nil))
	return nil
}

// VerifyDirective recomputes the signature with key. A directive altered by one
// byte -- a flipped stop, a changed node id, a bumped seq -- fails.
func VerifyDirective(d Directive, key []byte) (bool, string) {
	if d.Signature == "" {
		return false, "unsigned"
	}
	want, err := hex.DecodeString(d.Signature)
	if err != nil {
		return false, "malformed_signature"
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(DirectiveCanonicalString(d)))
	if !hmac.Equal(mac.Sum(nil), want) {
		return false, "signature_mismatch"
	}
	return true, "verified"
}

// FetchDirective polls the control plane for this node's current directive over
// an outbound bearer-authenticated GET. A 204 (no directive configured) returns
// the zero Directive with ok=false so the caller leaves local state untouched.
func FetchDirective(ctx context.Context, client *http.Client, url, token string) (Directive, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Directive{}, false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return Directive{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return Directive{}, false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return Directive{}, false, fmt.Errorf("control plane directive fetch: status %d: %s", resp.StatusCode, bytes.TrimSpace(snippet))
	}
	var d Directive
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&d); err != nil {
		return Directive{}, false, err
	}
	return d, true, nil
}
