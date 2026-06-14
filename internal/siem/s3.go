package siem

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// PutObjectAPI is the minimal slice of the S3 client surface the
// emitter needs. Defined as an interface so tests can inject a fake
// without dragging in the real AWS SDK plumbing.
type PutObjectAPI interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// S3Config configures the S3 sink emitter.
//
// The S3 sink lands audit events in an Amazon S3 bucket as gzipped
// NDJSON, partitioned Hive-style (year=YYYY/month=MM/day=DD/hour=HH).
// Hive partitioning lets Amazon Athena and AWS Glue prune partitions
// at query time without an MSCK REPAIR or per-day partition register.
//
// # Authentication
//
// Credentials come from the default AWS credential chain: env vars,
// shared config file, EC2 instance role, EKS Pod Identity, IRSA.
// The gateway pod typically runs with an IRSA role; no static keys
// in environment variables.
//
// # Encryption at rest
//
// Bucket-level SSE-S3 or SSE-KMS encryption is assumed (set on the
// bucket via lifecycle / default-encryption configuration). The
// emitter does not set per-object encryption headers; relying on
// bucket defaults is the operator-friendly choice and works with
// AWS Config rules that enforce encryption.
//
// # Failure isolation
//
// Same contract as every other SIEM emitter: own buffer, own worker,
// drops on overflow, never blocks the request path. Flush errors are
// logged and the batch is dropped — the Postgres auditstore remains
// the durable record of every decision.
type S3Config struct {
	// Bucket is the destination S3 bucket. Required.
	Bucket string
	// Prefix is the key prefix prepended to every object. Default
	// "audit/". Trailing slash is added if missing.
	Prefix string
	// Region is the AWS region the bucket lives in. When empty, the
	// SDK resolves it from AWS_REGION / AWS_DEFAULT_REGION / instance
	// metadata. Setting it explicitly is the recommended path for
	// multi-region operators routing audit to a specific region.
	Region string
	// KMSKeyID enables SSE-KMS with the named key for every PutObject.
	// When empty, the emitter relies on the bucket's default
	// encryption configuration. Use this when policy requires
	// per-object KMS key references (some regulated industries).
	KMSKeyID string
	// GatewayID is included in the object key to disambiguate writes
	// from multiple gateway replicas landing into the same bucket.
	// When empty, "gateway" is used.
	GatewayID string
	// Client is the S3 client used for PutObject. nil falls back to
	// the SDK default. Tests inject a stub.
	Client PutObjectAPI
	// FlushInterval overrides the batcher's default 5-second flush
	// cadence. Zero falls back to the package default. Exposed mainly
	// so tests can drive flushes quickly without sleeping the suite;
	// production deployments rarely need to set this.
	FlushInterval time.Duration
	// Logger receives drop / error notices. nil falls back to slog.Default.
	Logger *slog.Logger
}

// S3Emitter ships audit events to an S3 bucket as gzipped NDJSON.
//
// One object per flush. Object size depends on the batch size and
// the typical event JSON length; on a busy gateway with the default
// batch=100 events, a flushed object is on the order of 40-80 KiB
// gzipped. Small enough to keep S3 PUT cost negligible, large enough
// to keep Athena scan efficiency in the comfortable range.
type S3Emitter struct {
	cfg  S3Config
	be   *batchEmitter
	name string
}

// NewS3Emitter validates the config, constructs the emitter, and
// starts the worker. The AWS SDK is NOT contacted at startup; the
// first PutObject triggers credential resolution. Keeps pod startup
// fast and surfaces auth failures into the audit log rather than
// blocking the pod from coming up.
//
// Returns an error rather than a half-configured emitter so the
// gateway fails fast on misconfig.
func NewS3Emitter(cfg S3Config) (*S3Emitter, error) {
	if strings.TrimSpace(cfg.Bucket) == "" {
		return nil, errors.New("siem/s3: Bucket is required")
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "audit/"
	}
	if !strings.HasSuffix(cfg.Prefix, "/") {
		cfg.Prefix += "/"
	}
	if cfg.GatewayID == "" {
		cfg.GatewayID = "gateway"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Client == nil {
		client, err := defaultS3Client(cfg.Region)
		if err != nil {
			return nil, fmt.Errorf("siem/s3: load default config: %w", err)
		}
		cfg.Client = client
	}

	se := &S3Emitter{cfg: cfg, name: "s3"}
	se.be = newBatchEmitter(batchConfig{
		Name:          se.name,
		Flush:         se.flushOnce,
		FlushInterval: cfg.FlushInterval,
		Logger:        cfg.Logger,
	})
	return se, nil
}

// Emit forwards the event to the batched worker.
func (s *S3Emitter) Emit(ctx context.Context, ev audit.Event) {
	s.be.Emit(ctx, ev)
}

// Stop drains the worker.
func (s *S3Emitter) Stop(ctx context.Context) error { return s.be.Stop(ctx) }

// Status snapshots the emitter for the admin endpoint. The endpoint
// surfaces the bucket name (innocuous); credentials are never exposed.
func (s *S3Emitter) Status() Status {
	endpoint := "s3://" + s.cfg.Bucket + "/" + s.cfg.Prefix
	return s.be.counters.snapshot(s.name, endpoint, true)
}

// flushOnce serializes the batch to gzipped NDJSON and writes it to
// S3 under a Hive-partitioned key. Returns a transient error on
// throttling / 5xx so the worker logs it; the audit Postgres store
// remains the durable record so we do not buffer-and-retry here.
func (s *S3Emitter) flushOnce(ctx context.Context, events []audit.Event) error {
	if len(events) == 0 {
		return nil
	}

	// Use the FIRST event's timestamp for the partition prefix. A
	// flush typically spans a small wall-clock window (one flush
	// interval, default 5 seconds) so all events in a batch share
	// a partition; the rare cross-hour batch is still landed in one
	// hour's partition rather than split. Athena partition pruning
	// is robust to "an event whose ts is in hour N is filed under
	// partition N-1" — the WHERE clause filters on the event's own
	// ts field, not the prefix.
	t := parseEventTime(events[0].Timestamp)

	body, err := encodeNDJSONGzip(events)
	if err != nil {
		return fmt.Errorf("siem/s3: encode: %w", err)
	}

	key := s.objectKey(t)

	in := &s3.PutObjectInput{
		Bucket:          &s.cfg.Bucket,
		Key:             &key,
		Body:            bytes.NewReader(body),
		ContentType:     stringPtr("application/x-ndjson"),
		ContentEncoding: stringPtr("gzip"),
	}
	if s.cfg.KMSKeyID != "" {
		in.ServerSideEncryption = types.ServerSideEncryptionAwsKms
		in.SSEKMSKeyId = &s.cfg.KMSKeyID
	}

	if _, err := s.cfg.Client.PutObject(ctx, in); err != nil {
		// Classify transient vs permanent so the SIEM dashboard can
		// distinguish "AWS is having a bad afternoon" from "the
		// bucket policy is misconfigured". The SDK returns typed
		// errors; we sniff the HTTP status when available.
		if isTransientS3Error(err) {
			return &transientHTTPError{status: http.StatusServiceUnavailable}
		}
		return &permanentHTTPError{status: http.StatusForbidden}
	}
	return nil
}

// objectKey builds the Hive-partitioned object key for one flush.
//
// Shape:
//
//	<prefix>year=YYYY/month=MM/day=DD/hour=HH/<gateway-id>-<rfc3339>-<rand8>.ndjson.gz
//
// The trailing random suffix prevents two replicas flushing in the
// same second from racing on the same key. The RFC3339-shaped middle
// segment makes objects naturally sort by time inside a partition.
func (s *S3Emitter) objectKey(t time.Time) string {
	t = t.UTC()
	suffix := randHex8()
	name := fmt.Sprintf("%s-%s-%s.ndjson.gz",
		s.cfg.GatewayID,
		t.Format("20060102T150405Z"),
		suffix,
	)
	return path.Join(
		strings.TrimSuffix(s.cfg.Prefix, "/"),
		fmt.Sprintf("year=%04d", t.Year()),
		fmt.Sprintf("month=%02d", t.Month()),
		fmt.Sprintf("day=%02d", t.Day()),
		fmt.Sprintf("hour=%02d", t.Hour()),
		name,
	)
}

// encodeNDJSONGzip turns a batch into a gzipped NDJSON payload. One
// JSON object per line, newline-terminated, matches what AWS Glue's
// JSON SerDe (org.openx.data.jsonserde.JsonSerDe) reads natively.
func encodeNDJSONGzip(events []audit.Event) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	enc := json.NewEncoder(gz)
	for i := range events {
		if err := enc.Encode(&events[i]); err != nil {
			_ = gz.Close()
			return nil, err
		}
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// defaultS3Client builds an S3 client from the default AWS credential
// chain. Called only when the operator hasn't injected a custom
// PutObjectAPI — typically only true under tests.
func defaultS3Client(region string) (*s3.Client, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, err
	}
	return s3.NewFromConfig(cfg), nil
}

// isTransientS3Error sniffs the error for a 5xx-ish or throttling
// signal. The SDK returns typed errors but the surface area is wide;
// we err toward "transient" so a healthy bucket doesn't get marked
// as permanently broken by a one-off network hiccup.
func isTransientS3Error(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, hint := range []string{"throttl", "slowdown", "503", "500", "timeout", "i/o timeout", "tls", "connection reset"} {
		if strings.Contains(msg, hint) {
			return true
		}
	}
	return false
}

func stringPtr(s string) *string { return &s }

// randHex8 returns 8 random hex chars. Used as the trailing
// disambiguator on object keys. Crypto/rand because we don't want
// two replicas to ever collide on a key — a math/rand collision
// every few hundred million writes is bad for the operator's nerves
// even if S3 would tolerate the overwrite.
func randHex8() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to a deterministic-but-time-derived suffix; the
		// surrounding RFC3339 timestamp already gives second-level
		// uniqueness for one replica.
		return fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
	}
	return hex.EncodeToString(b[:])
}
