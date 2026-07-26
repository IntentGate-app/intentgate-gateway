package siem

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/eventbridge"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

type fakeEventBridge struct {
	calls   int
	entries int
	source  string
	detail  string
}

func (f *fakeEventBridge) PutEvents(_ context.Context, in *eventbridge.PutEventsInput, _ ...func(*eventbridge.Options)) (*eventbridge.PutEventsOutput, error) {
	f.calls++
	f.entries += len(in.Entries)
	if len(in.Entries) > 0 {
		if in.Entries[0].Source != nil {
			f.source = *in.Entries[0].Source
		}
		if in.Entries[0].Detail != nil {
			f.detail = *in.Entries[0].Detail
		}
	}
	return &eventbridge.PutEventsOutput{FailedEntryCount: 0}, nil
}

func TestEventBridgeFlushOneEntryPerEvent(t *testing.T) {
	fake := &fakeEventBridge{}
	em, err := NewEventBridgeEmitter(EventBridgeConfig{EventBusName: "intentgate", Client: fake})
	if err != nil {
		t.Fatalf("NewEventBridgeEmitter: %v", err)
	}
	events := []audit.Event{
		{Decision: audit.DecisionAllow, Tenant: "aws-prod"},
		{Decision: audit.DecisionBlock, Tenant: "aws-prod"},
	}
	if err := em.flush(context.Background(), events); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if fake.calls != 1 || fake.entries != 2 {
		t.Fatalf("want 1 call / 2 entries, got %d / %d", fake.calls, fake.entries)
	}
	if fake.source != "intentgate.gateway" {
		t.Errorf("default source = %q, want intentgate.gateway", fake.source)
	}
	if fake.detail == "" {
		t.Error("entry Detail should carry the event JSON")
	}
}

func TestEventBridgeEmptyBatchIsNoop(t *testing.T) {
	fake := &fakeEventBridge{}
	em, _ := NewEventBridgeEmitter(EventBridgeConfig{Client: fake})
	if err := em.flush(context.Background(), nil); err != nil {
		t.Fatalf("flush(nil): %v", err)
	}
	if fake.calls != 0 {
		t.Fatalf("empty batch should not call PutEvents, got %d", fake.calls)
	}
}
