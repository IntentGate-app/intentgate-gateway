package siem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	fhtypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// FirehoseConfig configures the native AWS Data Firehose adapter.
//
// Firehose is the managed delivery path on AWS: it buffers and lands records in
// S3, Redshift, OpenSearch, or a Splunk HEC without the customer running any
// consumer. This adapter puts one NDJSON record per decision, so an S3
// destination is queryable with Athena out of the box. Async downstream of the
// Telemetry Adapter Interface (same drops-not-blocks batch worker), reusing the
// default AWS credential chain like the S3 and Kinesis sinks.
type FirehoseConfig struct {
	// DeliveryStreamName is the destination Firehose stream. Required.
	DeliveryStreamName string
	// Region / Endpoint follow the same resolution as the other AWS sinks.
	Region   string
	Endpoint string
	// Client is injected in tests; nil builds the default client lazily.
	Client PutRecordBatchAPI
	// Logger receives drop / error notices. nil falls back to slog.Default.
	Logger *slog.Logger
}

// PutRecordBatchAPI is the one Firehose call this adapter makes.
type PutRecordBatchAPI interface {
	PutRecordBatch(ctx context.Context, in *firehose.PutRecordBatchInput, optFns ...func(*firehose.Options)) (*firehose.PutRecordBatchOutput, error)
}

// FirehoseEmitter delivers audit events to a Firehose stream, one newline-
// terminated JSON record per event so an S3 destination is valid NDJSON.
// Reuses the shared batch worker.
type FirehoseEmitter struct {
	cfg   FirehoseConfig
	be    *batchEmitter
	name  string
	label string
}

// NewFirehoseEmitter validates config, builds the client lazily, and starts the
// batch worker.
func NewFirehoseEmitter(cfg FirehoseConfig) (*FirehoseEmitter, error) {
	if strings.TrimSpace(cfg.DeliveryStreamName) == "" {
		return nil, errors.New("siem/firehose: DeliveryStreamName is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Client == nil {
		client, err := defaultFirehoseClient(cfg.Region, cfg.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("siem/firehose: load default config: %w", err)
		}
		cfg.Client = client
	}
	fe := &FirehoseEmitter{
		cfg:   cfg,
		name:  "firehose",
		label: "firehose://" + cfg.DeliveryStreamName,
	}
	fe.be = newBatchEmitter(batchConfig{
		Name:   fe.name,
		Flush:  fe.flush,
		Logger: cfg.Logger,
	})
	return fe, nil
}

// Emit forwards the event to the batched worker.
func (f *FirehoseEmitter) Emit(ctx context.Context, ev audit.Event) { f.be.Emit(ctx, ev) }

// Stop drains the batch worker.
func (f *FirehoseEmitter) Stop(ctx context.Context) error { return f.be.Stop(ctx) }

// Status snapshots the emitter for the admin endpoint. Stream name is exposed;
// credentials never are.
func (f *FirehoseEmitter) Status() Status {
	return f.be.snapshot(f.name, f.label, true)
}

// flush delivers the batch with one PutRecordBatch call, one newline-terminated
// JSON record per event. A partial failure (FailedPutCount > 0) or a request
// error is returned so the worker logs it; the audit Postgres store remains the
// durable record.
func (f *FirehoseEmitter) flush(ctx context.Context, events []audit.Event) error {
	if len(events) == 0 {
		return nil
	}
	recs := make([]fhtypes.Record, 0, len(events))
	for i := range events {
		b, err := json.Marshal(&events[i])
		if err != nil {
			continue
		}
		// Trailing newline so an S3 destination is valid NDJSON (one object per
		// line), which Athena / Glue read natively.
		b = append(b, '\n')
		recs = append(recs, fhtypes.Record{Data: b})
	}
	if len(recs) == 0 {
		return nil
	}

	out, err := f.cfg.Client.PutRecordBatch(ctx, &firehose.PutRecordBatchInput{
		DeliveryStreamName: stringPtr(f.cfg.DeliveryStreamName),
		Records:            recs,
	})
	if err != nil {
		return &transientHTTPError{status: 503}
	}
	if out != nil && out.FailedPutCount != nil && *out.FailedPutCount > 0 {
		return fmt.Errorf("siem/firehose: %d of %d records failed", *out.FailedPutCount, len(recs))
	}
	return nil
}

func defaultFirehoseClient(region, endpoint string) (PutRecordBatchAPI, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if strings.TrimSpace(region) != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, err
	}
	return firehose.NewFromConfig(cfg, func(o *firehose.Options) {
		if endpoint != "" {
			o.BaseEndpoint = &endpoint
		}
	}), nil
}
