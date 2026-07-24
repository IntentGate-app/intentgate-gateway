package siem

import "github.com/IntentGate-app/intentgate-gateway/internal/audit"

// Adapter is the Telemetry Adapter Interface: the single internal seam
// every telemetry destination plugs into. The core sub-millisecond
// decision path never talks to a transport directly — it emits to an
// [audit.Emitter], and each destination (Splunk, Datadog, Sentinel, an
// S3 cold tier, an OTLP collector, and roadmap adapters such as Kafka)
// is an Adapter behind this seam. That keeps the enforcement engine
// decoupled from, and never slowed by, whatever pipe the customer runs.
//
// An Adapter is three small contracts the rest of the package already
// relies on, named together so the design is explicit:
//
//   - audit.Emitter   — Emit(ctx, Event); MUST NOT block the request path.
//   - Stoppable       — Stop(ctx) drains the worker on graceful shutdown.
//   - StatusReporter   — Status() is the read-only snapshot the admin UI shows.
//
// Every adapter shares the same operational contract: a buffered
// worker that batches, flushes asynchronously, and drops on overflow
// rather than blocking. Emission is therefore always non-blocking and
// async, whichever adapter is selected.
type Adapter interface {
	audit.Emitter
	Stoppable
	StatusReporter
}

// Compile-time proof that every sink satisfies the one interface. The
// default, zero-new-infrastructure path is the OTLP exporter, the direct
// SIEM sinks, and the HTTPS webhook. Kafka is an opt-in enterprise-tier
// adapter that sits downstream on the async path (brokers must be
// configured; off by default).
var (
	_ Adapter = (*SplunkEmitter)(nil)
	_ Adapter = (*DatadogEmitter)(nil)
	_ Adapter = (*SentinelEmitter)(nil)
	_ Adapter = (*S3Emitter)(nil)
	_ Adapter = (*OTLPEmitter)(nil)
	_ Adapter = (*WebhookEmitter)(nil)
	_ Adapter = (*KafkaEmitter)(nil)
)
