package siem

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kinesis"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// fakeKinesis captures the records handed to PutRecords so a test can assert
// the flush shape without the AWS SDK or a live stream.
type fakeKinesis struct {
	calls   int
	records []recordSeen
}

type recordSeen struct {
	partitionKey string
	tenant       string
	decision     string
}

func (f *fakeKinesis) PutRecords(_ context.Context, in *kinesis.PutRecordsInput, _ ...func(*kinesis.Options)) (*kinesis.PutRecordsOutput, error) {
	f.calls++
	for _, r := range in.Records {
		var ev audit.Event
		_ = json.Unmarshal(r.Data, &ev)
		pk := ""
		if r.PartitionKey != nil {
			pk = *r.PartitionKey
		}
		f.records = append(f.records, recordSeen{partitionKey: pk, tenant: ev.Tenant, decision: string(ev.Decision)})
	}
	var zero int32
	return &kinesis.PutRecordsOutput{FailedRecordCount: &zero}, nil
}

func TestKinesisFlushOneRecordPerEventKeyedByTenant(t *testing.T) {
	fake := &fakeKinesis{}
	em, err := NewKinesisEmitter(KinesisConfig{StreamName: "intentgate.audit.v1", Client: fake})
	if err != nil {
		t.Fatalf("NewKinesisEmitter: %v", err)
	}

	events := []audit.Event{
		{Decision: audit.DecisionAllow, Tenant: "alibaba-prod"},
		{Decision: audit.DecisionBlock, Tenant: "aws-prod"},
		{Decision: audit.DecisionAllow, Tenant: ""}, // no tenant -> random partition key
	}
	if err := em.flush(context.Background(), events); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if fake.calls != 1 {
		t.Fatalf("want one PutRecords call, got %d", fake.calls)
	}
	if len(fake.records) != 3 {
		t.Fatalf("want 3 records, got %d", len(fake.records))
	}
	// Tenant becomes the partition key so a tenant's events stay on one shard.
	if fake.records[0].partitionKey != "alibaba-prod" {
		t.Errorf("record 0 partition key = %q, want alibaba-prod", fake.records[0].partitionKey)
	}
	if fake.records[1].partitionKey != "aws-prod" {
		t.Errorf("record 1 partition key = %q, want aws-prod", fake.records[1].partitionKey)
	}
	// An event with no tenant still gets a non-empty (random) partition key so
	// unkeyed traffic spreads across shards rather than hot-spotting shard 0.
	if fake.records[2].partitionKey == "" {
		t.Error("record 2 (no tenant) should have a non-empty random partition key")
	}
}

func TestKinesisRequiresStreamName(t *testing.T) {
	if _, err := NewKinesisEmitter(KinesisConfig{Client: &fakeKinesis{}}); err == nil {
		t.Fatal("expected an error when StreamName is empty")
	}
}

func TestKinesisEmptyBatchIsNoop(t *testing.T) {
	fake := &fakeKinesis{}
	em, err := NewKinesisEmitter(KinesisConfig{StreamName: "s", Client: fake})
	if err != nil {
		t.Fatalf("NewKinesisEmitter: %v", err)
	}
	if err := em.flush(context.Background(), nil); err != nil {
		t.Fatalf("flush(nil): %v", err)
	}
	if fake.calls != 0 {
		t.Fatalf("empty batch should not call PutRecords, got %d calls", fake.calls)
	}
}
