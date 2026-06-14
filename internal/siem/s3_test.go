package siem

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// fakeS3 captures PutObject calls so the tests can assert on what
// the emitter would have sent without involving the real SDK.
type fakeS3 struct {
	mu      sync.Mutex
	calls   []s3.PutObjectInput
	bodies  [][]byte
	failNxt error // returned by the next PutObject if set
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNxt != nil {
		err := f.failNxt
		f.failNxt = nil
		return nil, err
	}
	body, _ := io.ReadAll(in.Body)
	f.bodies = append(f.bodies, body)
	// Copy the input minus the body (already drained) so tests can
	// inspect the key, bucket, headers, etc.
	cp := *in
	f.calls = append(f.calls, cp)
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) snapshot() ([]s3.PutObjectInput, [][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	calls := append([]s3.PutObjectInput(nil), f.calls...)
	bodies := append([][]byte(nil), f.bodies...)
	return calls, bodies
}

func sampleEvent(ts string) audit.Event {
	return audit.Event{
		Timestamp:     ts,
		EventName:     "intentgate.tool_call",
		SchemaVersion: "v4",
		Decision:      audit.DecisionAllow,
		Tenant:        "acme",
		AgentID:       "agent-7",
		Tool:          "read_invoice",
		LatencyMS:     12,
	}
}

func TestS3Emitter_KeyShape(t *testing.T) {
	fake := &fakeS3{}
	em, err := NewS3Emitter(S3Config{
		Bucket:    "audit-bucket",
		Prefix:    "audit/",
		GatewayID: "gw-1",
		Client:    fake,
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	defer em.Stop(context.Background())

	// Drive an explicit flush by calling the internal flushOnce so
	// the test isn't sensitive to the background ticker.
	ts := "2026-06-14T09:42:13Z"
	if err := em.flushOnce(context.Background(), []audit.Event{sampleEvent(ts)}); err != nil {
		t.Fatalf("flushOnce: %v", err)
	}

	calls, bodies := fake.snapshot()
	if len(calls) != 1 {
		t.Fatalf("want 1 PutObject, got %d", len(calls))
	}
	if got := *calls[0].Bucket; got != "audit-bucket" {
		t.Errorf("bucket: got %q want audit-bucket", got)
	}
	wantPrefixes := []string{
		"audit/year=2026/month=06/day=14/hour=09/gw-1-20260614T094213Z-",
	}
	for _, want := range wantPrefixes {
		if !strings.HasPrefix(*calls[0].Key, want) {
			t.Errorf("key %q does not start with %q", *calls[0].Key, want)
		}
	}
	if !strings.HasSuffix(*calls[0].Key, ".ndjson.gz") {
		t.Errorf("key %q does not end with .ndjson.gz", *calls[0].Key)
	}
	if *calls[0].ContentType != "application/x-ndjson" {
		t.Errorf("ContentType: got %q want application/x-ndjson", *calls[0].ContentType)
	}
	if *calls[0].ContentEncoding != "gzip" {
		t.Errorf("ContentEncoding: got %q want gzip", *calls[0].ContentEncoding)
	}
	if len(bodies) != 1 || len(bodies[0]) == 0 {
		t.Fatalf("no body captured")
	}
}

func TestS3Emitter_BodyIsGzippedNDJSON(t *testing.T) {
	fake := &fakeS3{}
	em, err := NewS3Emitter(S3Config{Bucket: "b", Client: fake})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	defer em.Stop(context.Background())

	evs := []audit.Event{
		sampleEvent("2026-06-14T10:00:00Z"),
		sampleEvent("2026-06-14T10:00:01Z"),
	}
	if err := em.flushOnce(context.Background(), evs); err != nil {
		t.Fatalf("flushOnce: %v", err)
	}

	_, bodies := fake.snapshot()
	if len(bodies) != 1 {
		t.Fatalf("want 1 body, got %d", len(bodies))
	}

	gzr, err := gzip.NewReader(bytes.NewReader(bodies[0]))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gzr.Close()
	plain, err := io.ReadAll(gzr)
	if err != nil {
		t.Fatalf("read gunzipped: %v", err)
	}

	lines := bytes.Split(bytes.TrimRight(plain, "\n"), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("want 2 NDJSON lines, got %d (body=%q)", len(lines), plain)
	}
	for i, line := range lines {
		var ev audit.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Errorf("line %d not valid JSON: %v", i, err)
		}
	}
}

func TestS3Emitter_KMSHeader(t *testing.T) {
	fake := &fakeS3{}
	em, err := NewS3Emitter(S3Config{
		Bucket:   "b",
		KMSKeyID: "alias/audit",
		Client:   fake,
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	defer em.Stop(context.Background())

	if err := em.flushOnce(context.Background(), []audit.Event{sampleEvent("2026-06-14T10:00:00Z")}); err != nil {
		t.Fatalf("flushOnce: %v", err)
	}

	calls, _ := fake.snapshot()
	if calls[0].ServerSideEncryption != types.ServerSideEncryptionAwsKms {
		t.Errorf("SSE: got %v want %v", calls[0].ServerSideEncryption, types.ServerSideEncryptionAwsKms)
	}
	if calls[0].SSEKMSKeyId == nil || *calls[0].SSEKMSKeyId != "alias/audit" {
		t.Errorf("SSEKMSKeyId: got %v want alias/audit", calls[0].SSEKMSKeyId)
	}
}

func TestS3Emitter_NoKMSWhenUnset(t *testing.T) {
	fake := &fakeS3{}
	em, err := NewS3Emitter(S3Config{Bucket: "b", Client: fake})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	defer em.Stop(context.Background())

	if err := em.flushOnce(context.Background(), []audit.Event{sampleEvent("2026-06-14T10:00:00Z")}); err != nil {
		t.Fatalf("flushOnce: %v", err)
	}

	calls, _ := fake.snapshot()
	if calls[0].ServerSideEncryption != "" {
		t.Errorf("SSE: got %q want empty (bucket default)", calls[0].ServerSideEncryption)
	}
	if calls[0].SSEKMSKeyId != nil {
		t.Errorf("SSEKMSKeyId: got %v want nil", calls[0].SSEKMSKeyId)
	}
}

func TestS3Emitter_FlushTransientError(t *testing.T) {
	fake := &fakeS3{failNxt: errors.New("ServiceUnavailable: 503 slowdown")}
	em, err := NewS3Emitter(S3Config{Bucket: "b", Client: fake})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	defer em.Stop(context.Background())

	err = em.flushOnce(context.Background(), []audit.Event{sampleEvent("2026-06-14T10:00:00Z")})
	if err == nil {
		t.Fatal("want error, got nil")
	}
	var transient *transientHTTPError
	if !errors.As(err, &transient) {
		t.Errorf("want transient error, got %T: %v", err, err)
	}
}

func TestS3Emitter_FlushPermanentError(t *testing.T) {
	fake := &fakeS3{failNxt: errors.New("AccessDenied: bucket policy denies put")}
	em, err := NewS3Emitter(S3Config{Bucket: "b", Client: fake})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	defer em.Stop(context.Background())

	err = em.flushOnce(context.Background(), []audit.Event{sampleEvent("2026-06-14T10:00:00Z")})
	if err == nil {
		t.Fatal("want error, got nil")
	}
	var perm *permanentHTTPError
	if !errors.As(err, &perm) {
		t.Errorf("want permanent error, got %T: %v", err, err)
	}
}

func TestS3Emitter_RequiresBucket(t *testing.T) {
	_, err := NewS3Emitter(S3Config{Bucket: "  "})
	if err == nil {
		t.Fatal("want error on empty bucket")
	}
}

func TestS3Emitter_PrefixNormalisation(t *testing.T) {
	fake := &fakeS3{}
	em, err := NewS3Emitter(S3Config{
		Bucket: "b",
		Prefix: "custom/audit", // no trailing slash
		Client: fake,
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	defer em.Stop(context.Background())

	if err := em.flushOnce(context.Background(), []audit.Event{sampleEvent("2026-06-14T10:00:00Z")}); err != nil {
		t.Fatalf("flushOnce: %v", err)
	}
	calls, _ := fake.snapshot()
	if !strings.HasPrefix(*calls[0].Key, "custom/audit/year=") {
		t.Errorf("key %q: prefix normalisation broken", *calls[0].Key)
	}
}

func TestS3Emitter_StatusReportsBucket(t *testing.T) {
	fake := &fakeS3{}
	em, err := NewS3Emitter(S3Config{Bucket: "audit-bucket", Prefix: "tenants/acme/", Client: fake})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	defer em.Stop(context.Background())

	st := em.Status()
	if st.Name != "s3" {
		t.Errorf("Name: got %q want s3", st.Name)
	}
	if st.Endpoint != "s3://audit-bucket/tenants/acme/" {
		t.Errorf("Endpoint: got %q", st.Endpoint)
	}
	if !st.Configured {
		t.Error("Configured: want true")
	}
}

func TestS3Emitter_EmptyBatchIsNoOp(t *testing.T) {
	fake := &fakeS3{}
	em, err := NewS3Emitter(S3Config{Bucket: "b", Client: fake})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	defer em.Stop(context.Background())

	if err := em.flushOnce(context.Background(), nil); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
	calls, _ := fake.snapshot()
	if len(calls) != 0 {
		t.Errorf("want 0 calls on empty batch, got %d", len(calls))
	}
}

func TestS3Emitter_EmitThroughBatcher(t *testing.T) {
	// Smoke test that wiring through batchEmitter.Emit eventually
	// produces a flushed object. Uses a short flush interval passed
	// in at construction so the batcher worker reads the value
	// before the test goroutine could possibly mutate anything
	// (race detector lives here).
	fake := &fakeS3{}
	em, err := NewS3Emitter(S3Config{
		Bucket:        "b",
		Client:        fake,
		FlushInterval: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	em.Emit(context.Background(), sampleEvent("2026-06-14T10:00:00Z"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		calls, _ := fake.snapshot()
		if len(calls) >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	calls, _ := fake.snapshot()
	if len(calls) == 0 {
		t.Fatal("no flush observed after 2s")
	}
	_ = em.Stop(context.Background())
}
