package siem

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// EventBridgeConfig configures the native AWS EventBridge telemetry adapter.
//
// EventBridge is the event-bus target on AWS: a customer routing IntentGate
// decisions to Lambda, Step Functions, or partner SaaS via rules gets them on
// the same bus. Async downstream of the Telemetry Adapter Interface (same
// drops-not-blocks batch worker as every sink), reusing the default AWS
// credential chain exactly like the S3 and Kinesis sinks.
type EventBridgeConfig struct {
	// EventBusName is the destination bus. Empty uses AWS's "default" bus.
	EventBusName string
	// Source and DetailType tag every entry (EventBridge rules match on them).
	// Defaults: "intentgate.gateway" and "IntentGate Decision".
	Source     string
	DetailType string
	// Region / Endpoint follow the same resolution as the other AWS sinks.
	Region   string
	Endpoint string
	// Client is injected in tests; nil builds the default client lazily.
	Client PutEventsAPI
	// Logger receives drop / error notices. nil falls back to slog.Default.
	Logger *slog.Logger
}

// PutEventsAPI is the one EventBridge call this adapter makes.
type PutEventsAPI interface {
	PutEvents(ctx context.Context, in *eventbridge.PutEventsInput, optFns ...func(*eventbridge.Options)) (*eventbridge.PutEventsOutput, error)
}

// EventBridgeEmitter puts audit events onto an EventBridge bus, one entry per
// event with the event JSON as the Detail. Reuses the shared batch worker.
type EventBridgeEmitter struct {
	cfg   EventBridgeConfig
	be    *batchEmitter
	name  string
	label string
}

// NewEventBridgeEmitter validates config, builds the client lazily, and starts
// the batch worker.
func NewEventBridgeEmitter(cfg EventBridgeConfig) (*EventBridgeEmitter, error) {
	if cfg.Source == "" {
		cfg.Source = "intentgate.gateway"
	}
	if cfg.DetailType == "" {
		cfg.DetailType = "IntentGate Decision"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Client == nil {
		client, err := defaultEventBridgeClient(cfg.Region, cfg.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("siem/eventbridge: load default config: %w", err)
		}
		cfg.Client = client
	}
	bus := cfg.EventBusName
	if bus == "" {
		bus = "default"
	}
	eb := &EventBridgeEmitter{
		cfg:   cfg,
		name:  "eventbridge",
		label: "eventbridge://" + bus,
	}
	eb.be = newBatchEmitter(batchConfig{
		Name:   eb.name,
		Flush:  eb.flush,
		Logger: cfg.Logger,
	})
	return eb, nil
}

// Emit forwards the event to the batched worker.
func (e *EventBridgeEmitter) Emit(ctx context.Context, ev audit.Event) { e.be.Emit(ctx, ev) }

// Stop drains the batch worker.
func (e *EventBridgeEmitter) Stop(ctx context.Context) error { return e.be.Stop(ctx) }

// Status snapshots the emitter for the admin endpoint. Bus name is exposed;
// credentials never are.
func (e *EventBridgeEmitter) Status() Status {
	return e.be.snapshot(e.name, e.label, true)
}

// flush puts the batch with one PutEvents call, one entry per event. A partial
// failure (FailedEntryCount > 0) or a request error is returned so the worker
// logs it; the audit Postgres store remains the durable record.
func (e *EventBridgeEmitter) flush(ctx context.Context, events []audit.Event) error {
	if len(events) == 0 {
		return nil
	}
	var busPtr *string
	if e.cfg.EventBusName != "" {
		busPtr = stringPtr(e.cfg.EventBusName)
	}
	entries := make([]ebtypes.PutEventsRequestEntry, 0, len(events))
	for i := range events {
		b, err := json.Marshal(&events[i])
		if err != nil {
			continue
		}
		entries = append(entries, ebtypes.PutEventsRequestEntry{
			Source:       stringPtr(e.cfg.Source),
			DetailType:   stringPtr(e.cfg.DetailType),
			Detail:       stringPtr(string(b)),
			EventBusName: busPtr,
		})
	}
	if len(entries) == 0 {
		return nil
	}

	out, err := e.cfg.Client.PutEvents(ctx, &eventbridge.PutEventsInput{Entries: entries})
	if err != nil {
		return &transientHTTPError{status: 503}
	}
	if out != nil && out.FailedEntryCount > 0 {
		return fmt.Errorf("siem/eventbridge: %d of %d entries failed", out.FailedEntryCount, len(entries))
	}
	return nil
}

func defaultEventBridgeClient(region, endpoint string) (PutEventsAPI, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if strings.TrimSpace(region) != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, err
	}
	return eventbridge.NewFromConfig(cfg, func(o *eventbridge.Options) {
		if endpoint != "" {
			o.BaseEndpoint = &endpoint
		}
	}), nil
}
