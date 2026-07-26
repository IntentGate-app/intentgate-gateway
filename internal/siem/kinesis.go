package siem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// KinesisConfig configures the native AWS Kinesis Data Streams adapter.
//
// Kinesis is a first-class per-cloud streaming target on AWS: a customer who
// already runs a Kinesis backbone (and Firehose / Lambda / OpenSearch consumers
// off it) gets IntentGate decisions on the same rails, without standing up
// Kafka. Like every adapter it sits DOWNSTREAM of the Telemetry Adapter
// Interface on the async path, so a throttled or unavailable stream can never
// add latency to the inline decision: the shared batch worker drops on a full
// buffer rather than waiting.
type KinesisConfig struct {
	// StreamName is the destination Kinesis data stream. Required.
	StreamName string
	// Region is the AWS region the stream lives in. Empty falls back to the
	// default resolution of the AWS credential chain (AWS_REGION, config).
	Region string
	// Endpoint optionally overrides the service endpoint, for a VPC endpoint
	// or a Kinesis-compatible local (localstack) in tests. Empty targets real
	// AWS Kinesis.
	Endpoint string
	// Credentials come from the default AWS credential chain: env vars, an
	// IRSA / IAM-role-for-service-account token, or the instance role. The
	// gateway never holds a long-lived key of its own.
	//
	// Client is injected in tests; nil builds the default client lazily.
	Client PutRecordsAPI
	// Logger receives drop / error notices. nil falls back to slog.Default.
	Logger *slog.Logger
}

// PutRecordsAPI is the one Kinesis call this adapter makes, named as an
// interface so a test can substitute a fake without the AWS SDK.
type PutRecordsAPI interface {
	PutRecords(ctx context.Context, in *kinesis.PutRecordsInput, optFns ...func(*kinesis.Options)) (*kinesis.PutRecordsOutput, error)
}

// KinesisEmitter produces audit events to a Kinesis data stream, one record
// per event, keyed by tenant so a multi-cloud SOC can partition by trust
// domain the same way the Kafka adapter does. It reuses the shared batch
// worker for the non-blocking, drops-not-blocks contract every adapter shares.
type KinesisEmitter struct {
	cfg   KinesisConfig
	be    *batchEmitter
	name  string
	label string
}

// NewKinesisEmitter validates config, builds the client lazily (the SDK is not
// contacted until the first flush, keeping pod startup fast), and starts the
// batch worker.
func NewKinesisEmitter(cfg KinesisConfig) (*KinesisEmitter, error) {
	if strings.TrimSpace(cfg.StreamName) == "" {
		return nil, errors.New("siem/kinesis: StreamName is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Client == nil {
		client, err := defaultKinesisClient(cfg.Region, cfg.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("siem/kinesis: load default config: %w", err)
		}
		cfg.Client = client
	}

	ke := &KinesisEmitter{
		cfg:   cfg,
		name:  "kinesis",
		label: "kinesis://" + cfg.StreamName,
	}
	ke.be = newBatchEmitter(batchConfig{
		Name:   ke.name,
		Flush:  ke.flush,
		Logger: cfg.Logger,
	})
	return ke, nil
}

// Emit forwards the event to the batched worker.
func (k *KinesisEmitter) Emit(ctx context.Context, ev audit.Event) { k.be.Emit(ctx, ev) }

// Stop drains the batch worker.
func (k *KinesisEmitter) Stop(ctx context.Context) error { return k.be.Stop(ctx) }

// Status snapshots the emitter for the admin endpoint. The stream name is
// surfaced (innocuous); credentials never are.
func (k *KinesisEmitter) Status() Status {
	return k.be.snapshot(k.name, k.label, true)
}

// flush produces the batch with one PutRecords call, one record per event.
// A partial failure (FailedRecordCount > 0) or a request error is returned as
// transient so the worker logs it; the audit Postgres store remains the
// durable record, so we do not buffer-and-retry here (matching the S3 sink).
func (k *KinesisEmitter) flush(ctx context.Context, events []audit.Event) error {
	if len(events) == 0 {
		return nil
	}
	recs := make([]kinesistypes.PutRecordsRequestEntry, 0, len(events))
	for i := range events {
		b, err := json.Marshal(&events[i])
		if err != nil {
			continue
		}
		// Key by tenant so all of a tenant's events hash to the same shard,
		// preserving per-tenant ordering; a random key spreads unkeyed events
		// across shards rather than hot-spotting shard 0.
		pk := events[i].Tenant
		if pk == "" {
			pk = randHex8()
		}
		recs = append(recs, kinesistypes.PutRecordsRequestEntry{
			Data:         b,
			PartitionKey: stringPtr(pk),
		})
	}
	if len(recs) == 0 {
		return nil
	}

	out, err := k.cfg.Client.PutRecords(ctx, &kinesis.PutRecordsInput{
		StreamName: stringPtr(k.cfg.StreamName),
		Records:    recs,
	})
	if err != nil {
		return &transientHTTPError{status: 503}
	}
	if out != nil && out.FailedRecordCount != nil && *out.FailedRecordCount > 0 {
		return fmt.Errorf("siem/kinesis: %d of %d records failed", *out.FailedRecordCount, len(recs))
	}
	return nil
}

// defaultKinesisClient builds a Kinesis client from the default AWS credential
// chain, mirroring defaultS3Client so both AWS sinks resolve credentials the
// same way.
func defaultKinesisClient(region, endpoint string) (PutRecordsAPI, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, err
	}
	return kinesis.NewFromConfig(cfg, func(o *kinesis.Options) {
		if endpoint != "" {
			o.BaseEndpoint = &endpoint
		}
	}), nil
}
