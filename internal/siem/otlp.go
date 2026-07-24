package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// OTLPConfig configures the OpenTelemetry (OTLP/HTTP) logs exporter.
//
// This is the lean-default, zero-new-infrastructure telemetry path: the
// gateway emits each audit event as an OTLP LogRecord straight to the
// OTLP collector the customer already runs (an OpenTelemetry Collector,
// or a vendor OTLP endpoint at Datadog, Grafana, New Relic, and so on).
// No Kafka, no broker, no extra queue.
type OTLPConfig struct {
	// Endpoint is the OTLP/HTTP receiver. Either the signal-specific
	// logs URL ("https://collector.example.com:4318/v1/logs") or the
	// base endpoint ("https://collector.example.com:4318"), in which
	// case "/v1/logs" is appended per the OTLP/HTTP spec. Required.
	Endpoint string
	// ServiceName sets the resource attribute "service.name". Defaults
	// to "intentgate".
	ServiceName string
	// Namespace sets the optional resource attribute "service.namespace"
	// (handy for multi-tenant estates). Empty omits it.
	Namespace string
	// Headers are extra HTTP headers on every export, typically an auth
	// header the collector or vendor requires (for example
	// {"api-key": "..."} or {"Authorization": "Bearer ..."}). Never
	// logged or surfaced in Status.
	Headers map[string]string
	// HTTPClient is injected in tests; nil falls back to a default
	// client with a 30-second total timeout.
	HTTPClient *http.Client
	// Logger receives drop / error notices. nil falls back to slog.Default.
	Logger *slog.Logger
}

// OTLPEmitter ships audit events to an OTLP/HTTP logs endpoint. Each
// batched flush is one HTTP POST carrying an ExportLogsServiceRequest
// (OTLP/JSON encoding), so a single round trip carries the whole batch.
type OTLPEmitter struct {
	cfg      OTLPConfig
	be       *batchEmitter
	name     string
	logsURL  string
	resAttrs []otlpKeyValue
}

// NewOTLPEmitter validates config, builds the emitter, and starts its
// worker. Returns an error rather than a half-configured emitter so the
// gateway fails fast on misconfig.
func NewOTLPEmitter(cfg OTLPConfig) (*OTLPEmitter, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, errors.New("siem/otlp: Endpoint is required")
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "intentgate"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	resAttrs := []otlpKeyValue{stringAttr("service.name", cfg.ServiceName)}
	if cfg.Namespace != "" {
		resAttrs = append(resAttrs, stringAttr("service.namespace", cfg.Namespace))
	}

	oe := &OTLPEmitter{
		cfg:      cfg,
		name:     "otlp",
		logsURL:  otlpLogsURL(cfg.Endpoint),
		resAttrs: resAttrs,
	}
	oe.be = newBatchEmitter(batchConfig{
		Name:   oe.name,
		Flush:  httpFlusher(cfg.HTTPClient, oe.buildRequest),
		Logger: cfg.Logger,
	})
	return oe, nil
}

// Emit forwards the event to the batched worker.
func (o *OTLPEmitter) Emit(ctx context.Context, ev audit.Event) { o.be.Emit(ctx, ev) }

// Stop drains the worker.
func (o *OTLPEmitter) Stop(ctx context.Context) error { return o.be.Stop(ctx) }

// Status snapshots the emitter for the admin endpoint. The endpoint URL
// is exposed; the headers (which may carry an API key) never are.
func (o *OTLPEmitter) Status() Status {
	return o.be.counters.snapshot(o.name, o.logsURL, true)
}

// otlpLogsURL returns the logs signal URL. If the operator already gave
// a "/v1/logs" URL it is used verbatim; otherwise the OTLP/HTTP default
// path is appended to the base endpoint.
func otlpLogsURL(endpoint string) string {
	e := strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if strings.HasSuffix(e, "/v1/logs") {
		return e
	}
	return e + "/v1/logs"
}

func (o *OTLPEmitter) buildRequest(events []audit.Event) (*http.Request, error) {
	records := make([]otlpLogRecord, 0, len(events))
	for _, ev := range events {
		records = append(records, o.toLogRecord(ev))
	}
	payload := otlpExportLogs{
		ResourceLogs: []otlpResourceLogs{{
			Resource: otlpResource{Attributes: o.resAttrs},
			ScopeLogs: []otlpScopeLogs{{
				Scope:      otlpScope{Name: "intentgate-gateway"},
				LogRecords: records,
			}},
		}},
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(payload); err != nil {
		return nil, fmt.Errorf("siem/otlp: encode: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, o.logsURL, &buf)
	if err != nil {
		return nil, fmt.Errorf("siem/otlp: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range o.cfg.Headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// toLogRecord maps one audit.Event onto an OTLP LogRecord: the body is
// the human-readable summary, the decision drives severity, and the
// structured fields become log attributes. Only hashes and metadata are
// attached — never raw arguments or results.
func (o *OTLPEmitter) toLogRecord(ev audit.Event) otlpLogRecord {
	t := parseEventTime(ev.Timestamp)
	sevNum, sevText := otlpSeverity(ev.Decision)

	body := ev.Summary
	if body == "" {
		body = BuildSummary(ev)
	}

	attrs := []otlpKeyValue{
		stringAttr("intentgate.decision", string(ev.Decision)),
		stringAttr("intentgate.tool", ev.Tool),
	}
	attrs = appendIfSet(attrs, "intentgate.agent_id", ev.AgentID)
	attrs = appendIfSet(attrs, "intentgate.tenant", ev.Tenant)
	attrs = appendIfSet(attrs, "intentgate.check", string(ev.Check))
	attrs = appendIfSet(attrs, "intentgate.reason", ev.Reason)
	attrs = appendIfSet(attrs, "intentgate.event_id", ev.EventID)
	attrs = appendIfSet(attrs, "intentgate.session_id", ev.SessionID)
	attrs = appendIfSet(attrs, "intentgate.result_sha256", ev.ResultSHA256)
	attrs = appendIfSet(attrs, "event.name", ev.EventName)

	return otlpLogRecord{
		TimeUnixNano:   strconv.FormatInt(t.UnixNano(), 10),
		SeverityNumber: sevNum,
		SeverityText:   sevText,
		Body:           otlpAnyValue{StringValue: strPtr(body)},
		Attributes:     attrs,
	}
}

// otlpSeverity maps a decision onto the OTLP severity model: a block is
// an error, an escalation (held for a human) is a warning, everything
// else is informational.
func otlpSeverity(d audit.Decision) (int, string) {
	switch d {
	case audit.DecisionBlock:
		return 17, "ERROR"
	case audit.DecisionEscalate:
		return 13, "WARN"
	default:
		return 9, "INFO"
	}
}

func appendIfSet(attrs []otlpKeyValue, key, val string) []otlpKeyValue {
	if val == "" {
		return attrs
	}
	return append(attrs, stringAttr(key, val))
}

func stringAttr(key, val string) otlpKeyValue {
	return otlpKeyValue{Key: key, Value: otlpAnyValue{StringValue: strPtr(val)}}
}

func strPtr(s string) *string { return &s }

// --- OTLP/JSON wire types (ExportLogsServiceRequest subset) ---
//
// Hand-rolled rather than pulling in the OTel SDK: the logs payload we
// need is small and stable, and keeping it dependency-free preserves the
// "lean, no new infrastructure" promise for the default telemetry path.

type otlpExportLogs struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

type otlpResourceLogs struct {
	Resource  otlpResource    `json:"resource"`
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes,omitempty"`
}

type otlpScopeLogs struct {
	Scope      otlpScope       `json:"scope"`
	LogRecords []otlpLogRecord `json:"logRecords"`
}

type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type otlpLogRecord struct {
	// TimeUnixNano is a string: OTLP/JSON encodes 64-bit integers as
	// decimal strings to avoid JSON number precision loss.
	TimeUnixNano   string         `json:"timeUnixNano"`
	SeverityNumber int            `json:"severityNumber"`
	SeverityText   string         `json:"severityText"`
	Body           otlpAnyValue   `json:"body"`
	Attributes     []otlpKeyValue `json:"attributes,omitempty"`
}

type otlpKeyValue struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

type otlpAnyValue struct {
	StringValue *string `json:"stringValue,omitempty"`
}
