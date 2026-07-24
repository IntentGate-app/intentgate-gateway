package siem

import (
	"context"
	"errors"
	"log/slog"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// KafkaEmitter is a ROADMAP placeholder for the enterprise-tier Kafka
// telemetry adapter. It exists so the Telemetry Adapter Interface is
// real in code — the seam every transport plugs into — without pulling
// a Kafka client dependency into the gateway before the feature ships.
//
// It is deliberately NOT wireable: [NewKafkaEmitter] returns an error,
// so no deployment can accidentally enable a stub. The default,
// zero-new-infrastructure path is the OTLP exporter and the direct SIEM
// sinks; Kafka (and the managed cloud-eventing adapters — AWS
// EventBridge, Azure Event Hubs, GCP Pub/Sub, Alibaba ApsaraMQ, Tencent
// TDMQ, and so on) attach here later, on the same seam, only for
// customers who already run that backbone.
//
// Tracking: backlog #297 (Kafka event-streaming fabric).
type KafkaEmitter struct {
	name string
}

// KafkaConfig is the shape the future adapter will take. Present now so
// callers and docs can reference it; unused until the adapter ships.
type KafkaConfig struct {
	Brokers []string
	Topic   string
	Logger  *slog.Logger
}

// ErrKafkaAdapterNotImplemented is returned by [NewKafkaEmitter] until
// the enterprise-tier Kafka adapter is built.
var ErrKafkaAdapterNotImplemented = errors.New(
	"siem/kafka: the Kafka telemetry adapter is on the roadmap (backlog #297) and not yet implemented; " +
		"use the OTLP exporter (INTENTGATE_SIEM_OTLP_ENDPOINT) or a direct SIEM sink instead")

// NewKafkaEmitter always returns ErrKafkaAdapterNotImplemented. It is
// present so the wiring and the interface are honest today; it will
// return a working emitter when the adapter ships.
func NewKafkaEmitter(_ KafkaConfig) (*KafkaEmitter, error) {
	return nil, ErrKafkaAdapterNotImplemented
}

// Emit is a no-op. A KafkaEmitter value can never be constructed via the
// public constructor, so this is only here to satisfy the [Adapter]
// interface at compile time.
func (*KafkaEmitter) Emit(context.Context, audit.Event) {}

// Stop is a no-op.
func (*KafkaEmitter) Stop(context.Context) error { return nil }

// Status reports the adapter as present but not configured, so the admin
// UI can show it as an available-on-roadmap destination without claiming
// it is live.
func (k *KafkaEmitter) Status() Status {
	name := k.name
	if name == "" {
		name = "kafka"
	}
	return Status{Name: name, Configured: false}
}
