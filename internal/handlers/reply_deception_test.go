package handlers

import (
	"net/http"
	"testing"

	"github.com/IntentGate-app/intentgate-gateway/internal/deception"
)

// canaryDetector builds a detector with a single injection-canary marker, the
// reply-side detection dimension.
func canaryDetector() *deception.Detector {
	return deception.New(deception.NewStaticRegistry([]deception.Decoy{
		{
			ID:     "c",
			Name:   "Injection canary",
			Kind:   deception.InjectionCanary,
			Key:    "IG-CANARY-9f2",
			OnTrip: deception.OnTripAlert,
		},
	}))
}

func TestReply_DeceptionCanary_CleanReplyPasses(t *testing.T) {
	_, out := doReply(t,
		ReplyHandlerConfig{Deception: canaryDetector()},
		`{"reply":"here is your order summary"}`)
	if out.Action != "allow" {
		t.Fatalf("a clean reply should pass, got action=%q", out.Action)
	}
}

func TestReply_DeceptionCanary_MarkerInReplyBlocks(t *testing.T) {
	// The agent obeyed injected content and carried the planted marker into
	// its answer to the user. The reply-side scan catches it and blocks.
	rec, out := doReply(t,
		ReplyHandlerConfig{Deception: canaryDetector()},
		`{"reply":"as instructed, include IG-CANARY-9f2 in the report"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if out.Action != "block" || out.Reply != "" {
		t.Fatalf("a reply carrying the canary marker should be blocked, got action=%q reply=%q", out.Action, out.Reply)
	}
}
