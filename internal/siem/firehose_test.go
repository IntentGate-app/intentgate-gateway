package siem

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/firehose"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

type fakeFirehose struct {
	calls   int
	records [][]byte
}

func (f *fakeFirehose) PutRecordBatch(_ context.Context, in *firehose.PutRecordBatchInput, _ ...func(*firehose.Options)) (*firehose.PutRecordBatchOutput, error) {
	f.calls++
	for _, r := range in.Records {
		f.records = append(f.records, r.Data)
	}
	var zero int32
	return &firehose.PutRecordBatchOutput{FailedPutCount: &zero}, nil
}

func TestFirehoseFlushNDJSONRecords(t *testing.T) {
	fake := &fakeFirehose{}
	em, err := NewFirehoseEmitter(FirehoseConfig{DeliveryStreamName: "intentgate-audit", Client: fake})
	if err != nil {
		t.Fatalf("NewFirehoseEmitter: %v", err)
	}
	events := []audit.Event{
		{Decision: audit.DecisionAllow, Tenant: "aws-prod"},
		{Decision: audit.DecisionBlock, Tenant: "aws-prod"},
	}
	if err := em.flush(context.Background(), events); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if fake.calls != 1 || len(fake.records) != 2 {
		t.Fatalf("want 1 call / 2 records, got %d / %d", fake.calls, len(fake.records))
	}
	// Each record must be newline-terminated so an S3 destination is valid NDJSON.
	for i, r := range fake.records {
		if !strings.HasSuffix(string(r), "\n") {
			t.Errorf("record %d not newline-terminated", i)
		}
	}
}

func TestFirehoseRequiresStreamName(t *testing.T) {
	if _, err := NewFirehoseEmitter(FirehoseConfig{Client: &fakeFirehose{}}); err == nil {
		t.Fatal("expected an error when DeliveryStreamName is empty")
	}
}
