package siem

import (
	"context"
	"testing"
)

// These are config-validation tests only — they never dial a broker, so
// they run in CI without Kafka. Produce/consume behaviour is covered by
// the lab integration against a real Redpanda/Kafka broker.

func TestNewKafkaEmitterRequiresBrokers(t *testing.T) {
	if _, err := NewKafkaEmitter(KafkaConfig{Topic: "ig.audit.v1"}); err == nil {
		t.Fatal("expected error with no brokers")
	}
}

func TestNewKafkaEmitterRequiresTopic(t *testing.T) {
	if _, err := NewKafkaEmitter(KafkaConfig{Brokers: []string{"localhost:9092"}}); err == nil {
		t.Fatal("expected error with no topic")
	}
}

func TestNewKafkaEmitterOK(t *testing.T) {
	// franz-go connects lazily, so constructing a client with a seed
	// broker must not error or block.
	em, err := NewKafkaEmitter(KafkaConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "ig.audit.v1",
		Logger:  quietLogger(),
	})
	if err != nil {
		t.Fatalf("NewKafkaEmitter: %v", err)
	}
	if st := em.Status(); !st.Configured || st.Name != "kafka" {
		t.Errorf("unexpected status: %+v", st)
	}
	// Close the client; nothing was ever produced.
	_ = em.Stop(context.Background())
}
