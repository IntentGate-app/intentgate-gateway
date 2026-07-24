package siem

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"
)

// KafkaConfig configures the enterprise-tier Kafka telemetry adapter.
//
// Kafka sits DOWNSTREAM of the Telemetry Adapter Interface on the async
// path — it never touches the inline request path. Audit events are
// produced to a topic after the firewall decision has already returned,
// so a slow, rebalancing, or unreachable broker can never add latency to
// (or block) an agent's tool call: the shared batch worker drops on a
// full buffer rather than waiting.
//
// This adapter is opt-in and additive. The default, zero-new-
// infrastructure path stays the OTLP exporter and the direct SIEM sinks;
// Kafka is for customers who already run a Kafka / Confluent / Redpanda
// backbone and want the high-throughput durable fan-out to their SOC.
type KafkaConfig struct {
	// Brokers is the seed broker list, e.g. ["b1:9092","b2:9092"]. Required.
	Brokers []string
	// Topic is the destination topic. Required.
	Topic string
	// TLS enables a TLS dialer (TLS 1.2+). Use for managed brokers
	// (Confluent Cloud, MSK, Event Hubs Kafka API) and any broker with
	// TLS listeners.
	TLS bool
	// SASLUser / SASLPass enable SASL/PLAIN auth when both are set
	// (required by most managed Kafka). Never logged.
	SASLUser string
	SASLPass string
	// Logger receives drop / error notices. nil falls back to slog.Default.
	Logger *slog.Logger
}

// KafkaEmitter produces audit events to a Kafka topic via franz-go
// (pure Go, no CGo). It reuses the shared batch worker for the same
// non-blocking, drops-not-blocks contract every adapter shares.
type KafkaEmitter struct {
	cfg   KafkaConfig
	cl    *kgo.Client
	be    *batchEmitter
	name  string
	label string
}

// NewKafkaEmitter validates config, dials the client (lazily — franz-go
// connects on first produce), and starts the batch worker.
func NewKafkaEmitter(cfg KafkaConfig) (*KafkaEmitter, error) {
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("siem/kafka: at least one broker is required")
	}
	if strings.TrimSpace(cfg.Topic) == "" {
		return nil, errors.New("siem/kafka: Topic is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	opts := []kgo.Opt{
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.DefaultProduceTopic(cfg.Topic),
		kgo.ProducerBatchCompression(kgo.SnappyCompression()),
		kgo.ProducerLinger(50 * time.Millisecond),
		// Ask the broker to create the audit topic on first produce
		// (franz-go does not by default). Works where the broker allows
		// auto-creation; on brokers that forbid it by policy, pre-create
		// the topic (the adapter still drops-not-blocks until it exists).
		kgo.AllowAutoTopicCreation(),
		// franz-go defaults to an idempotent producer (acks=all), which
		// is exactly right for a durable, duplicate-free audit stream.
		// The gateway-side batch worker still drops-not-blocks, so
		// acks=all never adds latency to the inline firewall decision.
	}
	if cfg.TLS {
		opts = append(opts, kgo.DialTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12}))
	}
	if cfg.SASLUser != "" && cfg.SASLPass != "" {
		opts = append(opts, kgo.SASL(plain.Auth{User: cfg.SASLUser, Pass: cfg.SASLPass}.AsMechanism()))
	}

	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("siem/kafka: new client: %w", err)
	}

	ke := &KafkaEmitter{
		cfg:   cfg,
		cl:    cl,
		name:  "kafka",
		label: strings.Join(cfg.Brokers, ",") + " → " + cfg.Topic,
	}
	ke.be = newBatchEmitter(batchConfig{
		Name:   ke.name,
		Flush:  ke.flush,
		Logger: cfg.Logger,
	})
	return ke, nil
}

// Emit forwards the event to the batched worker.
func (k *KafkaEmitter) Emit(ctx context.Context, ev audit.Event) { k.be.Emit(ctx, ev) }

// Stop drains the batch worker, then closes the Kafka client (flushing
// any buffered records) within the caller's deadline.
func (k *KafkaEmitter) Stop(ctx context.Context) error {
	err := k.be.Stop(ctx)
	if k.cl != nil {
		_ = k.cl.Flush(ctx)
		k.cl.Close()
	}
	return err
}

// Status snapshots the emitter for the admin endpoint. The broker/topic
// label is exposed; SASL credentials never are.
func (k *KafkaEmitter) Status() Status {
	return k.be.counters.snapshot(k.name, k.label, true)
}

// flush produces the batch synchronously so any broker error propagates
// back to the worker (which logs it and clears the batch rather than
// blocking the gateway). One JSON record per audit event.
func (k *KafkaEmitter) flush(ctx context.Context, events []audit.Event) error {
	recs := make([]*kgo.Record, 0, len(events))
	for _, ev := range events {
		b, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		rec := &kgo.Record{Value: b}
		if ev.Tenant != "" {
			rec.Key = []byte(ev.Tenant)
		}
		recs = append(recs, rec)
	}
	if len(recs) == 0 {
		return nil
	}
	return k.cl.ProduceSync(ctx, recs...).FirstErr()
}
