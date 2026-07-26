package siem

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

func TestPubSubBuildRequestPublishesBase64(t *testing.T) {
	em, err := NewPubSubEmitter(PubSubConfig{
		ProjectID:   "my-proj",
		Topic:       "intentgate-audit",
		StaticToken: "test-token",
	})
	if err != nil {
		t.Fatalf("NewPubSubEmitter: %v", err)
	}

	events := []audit.Event{{Decision: audit.DecisionAllow, Tenant: "gcp-prod"}}
	req, err := em.buildRequest(events)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}

	if got := req.URL.String(); got != "https://pubsub.googleapis.com/v1/projects/my-proj/topics/intentgate-audit:publish" {
		t.Errorf("unexpected publish URL: %s", got)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer test-token" {
		t.Errorf("auth header = %q, want Bearer test-token", got)
	}

	body, _ := io.ReadAll(req.Body)
	var pub pubsubPublishRequest
	if err := json.Unmarshal(body, &pub); err != nil {
		t.Fatalf("body not valid publish JSON: %v", err)
	}
	if len(pub.Messages) != 1 {
		t.Fatalf("want 1 message, got %d", len(pub.Messages))
	}
	// data must be base64 of the event JSON, and the tenant attribute set.
	if _, err := base64.StdEncoding.DecodeString(pub.Messages[0].Data); err != nil {
		t.Errorf("message data is not base64: %v", err)
	}
	if pub.Messages[0].Attributes["tenant"] != "gcp-prod" {
		t.Errorf("tenant attribute = %q, want gcp-prod", pub.Messages[0].Attributes["tenant"])
	}
}

func TestPubSubRequiresProjectAndTopic(t *testing.T) {
	if _, err := NewPubSubEmitter(PubSubConfig{Topic: "t"}); err == nil {
		t.Fatal("expected error when ProjectID is empty")
	}
	if _, err := NewPubSubEmitter(PubSubConfig{ProjectID: "p"}); err == nil {
		t.Fatal("expected error when Topic is empty")
	}
}
