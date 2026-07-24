// Command gateway is the entrypoint for the IntentGate gateway.
//
// The gateway sits between AI agents and tool servers. It accepts tool-call
// requests over HTTP, evaluates them through the four-check pipeline
// (capability, intent, policy, budget), and either forwards the call to the
// upstream tool server or blocks it.
//
// In v0.1.0-dev the capability check is wired up; intent, policy, and
// budget land in subsequent sessions. Calls that pass capability are
// allowed with a stub reason.
//
// Configuration is via environment variables:
//
//	INTENTGATE_ADDR                 listen address (default ":8080")
//	INTENTGATE_MASTER_KEY           base64url HMAC key for capability tokens
//	                                (if unset, an ephemeral key is generated
//	                                and printed; tokens won't survive a
//	                                gateway restart)
//	INTENTGATE_REQUIRE_CAPABILITY   set to "true" to reject /v1/mcp calls
//	                                that don't carry a valid Bearer token
//	INTENTGATE_EXTRACTOR_URL        base URL of the intent extractor service,
//	                                e.g. "http://extractor:8090". When unset,
//	                                the intent check is disabled.
//	INTENTGATE_REQUIRE_INTENT       set to "true" to reject /v1/mcp calls
//	                                that don't carry an X-Intent-Prompt header
//	INTENTGATE_POLICY_FILE          path to a customer Rego policy file. When
//	                                unset, the embedded default policy is used.
//	INTENTGATE_REDIS_URL            Redis connection string for the budget
//	                                store, e.g. "redis://localhost:6379/0".
//	                                When unset, an in-memory store is used
//	                                (single-replica only).
//	INTENTGATE_REQUIRE_BUDGET       set to "true" to reject /v1/mcp calls
//	                                that lack a verified capability token
//	                                at the budget stage.
//	INTENTGATE_AUDIT_TARGET         where to emit audit events. Recognized
//	                                values: "stdout" (default), "none".
//	INTENTGATE_AUDIT_PERSIST        "true" to also persist every audit
//	                                event into the configured Postgres
//	                                (uses INTENTGATE_POSTGRES_URL). When
//	                                set, GET /v1/admin/audit becomes
//	                                queryable. Default off so existing
//	                                stdout-only deployments are unchanged.
//	INTENTGATE_SIEM_SPLUNK_URL      Splunk HEC endpoint URL. When set
//	                                with INTENTGATE_SIEM_SPLUNK_TOKEN,
//	                                every audit event also ships to
//	                                Splunk in batches.
//	INTENTGATE_SIEM_SPLUNK_TOKEN    Splunk HEC token (header value).
//	INTENTGATE_SIEM_SPLUNK_INDEX    Optional Splunk index. Empty routes
//	                                to the token's default index.
//	INTENTGATE_SIEM_DATADOG_API_KEY When set, every audit event also
//	                                ships to Datadog Logs Intake.
//	INTENTGATE_SIEM_DATADOG_SITE    Datadog regional site, default
//	                                "datadoghq.com".
//	INTENTGATE_SIEM_DATADOG_SERVICE Datadog "service" tag, default
//	                                "intentgate-gateway".
//	INTENTGATE_SIEM_SENTINEL_DCE_URL    Microsoft Sentinel Data
//	                                Collection Endpoint URL.
//	INTENTGATE_SIEM_SENTINEL_DCR_ID  Immutable ID of the Data
//	                                Collection Rule.
//	INTENTGATE_SIEM_SENTINEL_STREAM  Custom-table stream name, e.g.
//	                                "Custom-IntentGate_CL".
//	INTENTGATE_SIEM_SENTINEL_TENANT_ID    Azure AD tenant.
//	INTENTGATE_SIEM_SENTINEL_CLIENT_ID    Service-principal client ID.
//	INTENTGATE_SIEM_SENTINEL_CLIENT_SECRET  Service-principal secret.
//	                                All six are required together;
//	                                missing any disables the Sentinel
//	                                emitter (or fails fast if some
//	                                but not all are set).
//	INTENTGATE_APPROVALS_BACKEND   "memory" (default), "postgres", or
//	                                "off". When "postgres" the gateway
//	                                uses INTENTGATE_POSTGRES_URL for
//	                                the queue. "off" disables the
//	                                escalate path: a Rego policy
//	                                returning escalate becomes a block.
//	INTENTGATE_APPROVAL_TIMEOUT_S  How long the gateway waits for a
//	                                human decision before timing out
//	                                and returning block. Default 300
//	                                (5 minutes).
//	INTENTGATE_POLICY_STORE        "off" (default), "memory", or
//	                                "postgres". When "memory" or
//	                                "postgres", /v1/admin/policies/*
//	                                draft and active-pointer endpoints
//	                                register. "postgres" uses
//	                                INTENTGATE_POSTGRES_URL. Promotes
//	                                survive restarts only on
//	                                "postgres".
//	INTENTGATE_TENANT_ADMINS       Comma-separated tenant:token pairs
//	                                that scope admin operations to a
//	                                single tenant.
//	                                Example: "acme:tok-a,globex:tok-b".
//	                                Coexists with INTENTGATE_ADMIN_TOKEN
//	                                (the superadmin); a deployment can
//	                                set both, neither, or just one.
//	INTENTGATE_UPSTREAM_URL         URL of the downstream MCP tool server
//	                                authorized calls are forwarded to. When
//	                                unset, the gateway returns a stub allow
//	                                for any call that passes the four
//	                                checks (useful for SDK tests, smokes).
//	INTENTGATE_UPSTREAM_TIMEOUT_MS  per-call upstream timeout in
//	                                milliseconds. Default 30000.
//	INTENTGATE_UPSTREAM_AUTH_HEADER credential brokering: the real tool-
//	                                server credential as "Header-Name: value"
//	                                (e.g. "Authorization: Bearer sk-..."),
//	                                injected by the gateway on every
//	                                forwarded call so agents never hold the
//	                                upstream secret. Unset = none injected.
//	INTENTGATE_UPSTREAM_TOOL_CREDENTIALS
//	                                per-tool credential brokering: a JSON
//	                                object mapping tool -> "Header: value",
//	                                e.g. {"transfer_funds":"Authorization:
//	                                Bearer sk-pay"}. Each tool's call gets
//	                                its own credential; tools without an
//	                                entry use the global header above. With
//	                                INTENTGATE_POSTGRES_URL set, per-tool
//	                                credentials become console-managed and
//	                                encrypted at rest (this env only seeds
//	                                first boot).
//	INTENTGATE_CREDENTIAL_ENCRYPTION_KEY
//	                                32-byte AES key (64 hex chars) used to
//	                                encrypt per-tool credentials at rest.
//	                                Optional — derived from the master key
//	                                when unset.
//	INTENTGATE_POSTGRES_URL         libpq-style DSN for a Postgres-backed
//	                                revocation store, e.g.
//	                                "postgres://user:pass@host:5432/db".
//	                                When unset, an in-memory revocation
//	                                store is used (single-replica only,
//	                                lost on restart).
//	INTENTGATE_ADMIN_TOKEN          shared secret guarding /v1/admin/*
//	                                endpoints (revoke, list-revocations).
//	                                When unset, admin endpoints are
//	                                disabled (404 / not registered).
//	INTENTGATE_METRICS_ENABLED      "true" to register /metrics on the
//	                                public port. Default off because
//	                                exposing metrics on the same port
//	                                as agent traffic is an info-
//	                                disclosure risk for naive deploys.
//	OTEL_EXPORTER_OTLP_ENDPOINT     standard OTel env var. When set,
//	                                the gateway initializes an OTLP
//	                                gRPC exporter and emits one span
//	                                per HTTP request. Empty disables
//	                                tracing entirely (no overhead).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/actionguard"
	"github.com/IntentGate-app/intentgate-gateway/internal/approvals"
	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
	"github.com/IntentGate-app/intentgate-gateway/internal/auditstore"
	"github.com/IntentGate-app/intentgate-gateway/internal/budget"
	"github.com/IntentGate-app/intentgate-gateway/internal/capability"
	"github.com/IntentGate-app/intentgate-gateway/internal/credentials"
	"github.com/IntentGate-app/intentgate-gateway/internal/deception"
	"github.com/IntentGate-app/intentgate-gateway/internal/eastwest"
	"github.com/IntentGate-app/intentgate-gateway/internal/extractor"
	"github.com/IntentGate-app/intentgate-gateway/internal/faultisolation"
	"github.com/IntentGate-app/intentgate-gateway/internal/federation"
	"github.com/IntentGate-app/intentgate-gateway/internal/killswitch"
	"github.com/IntentGate-app/intentgate-gateway/internal/metrics"
	"github.com/IntentGate-app/intentgate-gateway/internal/outputschema"
	"github.com/IntentGate-app/intentgate-gateway/internal/pii"
	"github.com/IntentGate-app/intentgate-gateway/internal/policy"
	"github.com/IntentGate-app/intentgate-gateway/internal/policystore"
	"github.com/IntentGate-app/intentgate-gateway/internal/refverify"
	"github.com/IntentGate-app/intentgate-gateway/internal/revocation"
	"github.com/IntentGate-app/intentgate-gateway/internal/server"
	"github.com/IntentGate-app/intentgate-gateway/internal/siem"
	"github.com/IntentGate-app/intentgate-gateway/internal/task"
	"github.com/IntentGate-app/intentgate-gateway/internal/tenantscope"
	"github.com/IntentGate-app/intentgate-gateway/internal/upstream"
	"github.com/IntentGate-app/intentgate-gateway/internal/webhook"
	"github.com/IntentGate-app/intentgate-gateway/internal/zonescope"
	"github.com/redis/go-redis/v9"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// version is overridden at build time via -ldflags="-X main.version=...".
var version = "0.1.0-dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	addr := envOr("INTENTGATE_ADDR", ":8080")
	requireCap := envOr("INTENTGATE_REQUIRE_CAPABILITY", "") == "true"
	// Separation of duties on policy promotion. Off unless explicitly
	// asked for: see server.Config.RequirePolicyApproval.
	requirePolicyApproval := envOr("INTENTGATE_POLICY_REQUIRE_APPROVAL", "") == "true"
	requireIntent := envOr("INTENTGATE_REQUIRE_INTENT", "") == "true"
	requireBudget := envOr("INTENTGATE_REQUIRE_BUDGET", "") == "true"
	// Opt-in AAI03 (Memory Poisoning) defense. Off by default — the
	// gateway runs as the documented four-check pipeline. When set
	// to "true", a fifth check (provenance) runs between intent and
	// policy: requests carrying X-Intent-Memory-Provenance have
	// their declared memory entries HMAC-verified against a session
	// key derived from the capability token's jti. See
	// internal/provenance and memos/aai03-memory-provenance-design.md.
	provenanceEnabled := envOr("INTENTGATE_PROVENANCE_ENABLED", "") == "true"
	// Opt-in LLM02 (Sensitive Information Disclosure) defense. Off by
	// default — the gateway forwards tool-call requests and responses
	// without content inspection. When set to "true", the PII filter
	// runs on Check 6 in both directions:
	//   - Outbound: tool-call arguments scanned for PII before forwarding
	//     to the upstream (redacts or blocks per configuration).
	//   - Inbound: upstream tool-call responses scanned for PII before
	//     the agent receives bytes (redacts or blocks per configuration).
	// See internal/pii and gateway/docs/06-pii-filter.md.
	piiFilterEnabled := envOr("INTENTGATE_PII_FILTER_ENABLED", "") == "true"
	piiDefaultActionRaw := envOr("INTENTGATE_PII_DEFAULT_ACTION", "redact")
	piiPatternsRaw := envOr("INTENTGATE_PII_PATTERNS", "")
	piiPerPatternActionRaw := envOr("INTENTGATE_PII_PER_PATTERN_ACTION", "")
	// LLM05 output-schema registry. Reads a per-tool JSON-Schema-subset
	// config from disk at INTENTGATE_OUTPUT_SCHEMAS_PATH. Empty path =
	// no schemas declared = the check is a no-op for every tool.
	outputSchemasPath := envOr("INTENTGATE_OUTPUT_SCHEMAS_PATH", "")
	outputSchemasDefaultAction := envOr("INTENTGATE_OUTPUT_SCHEMA_DEFAULT_ACTION", "strip")
	// LLM08 per-tenant vector-scope enforcer. CSV of tool names with
	// optional :arg_path (e.g. "vector_search:tenant_id,rag_query:filter.tenant_id").
	// Empty disables the check (no-op).
	tenantScopeToolsRaw := envOr("INTENTGATE_TENANT_SCOPED_TOOLS", "")
	tenantScopeDefaultAction := envOr("INTENTGATE_TENANT_SCOPE_DEFAULT_ACTION", "block")
	// AGENT08 per-tool circuit-breaker + bulkhead. Disabled by default;
	// once enabled, every upstream forward is gated by a per-tool
	// semaphore + breaker.
	faultIsolationEnabled := envOr("INTENTGATE_FAULT_ISOLATION_ENABLED", "") == "true"
	faultIsolationMaxConcurrentRaw := envOr("INTENTGATE_FAULT_ISOLATION_MAX_CONCURRENT_PER_TOOL", "20")
	faultIsolationFailureThresholdRaw := envOr("INTENTGATE_FAULT_ISOLATION_FAILURE_THRESHOLD", "5")
	faultIsolationCooldownMSRaw := envOr("INTENTGATE_FAULT_ISOLATION_COOLDOWN_MS", "30000")
	// Action guard: effect-level enforcement (semantic Action IR resolver +
	// mandatory hold + plan-level correlation, #28). Off by default; the
	// gateway runs its documented pipeline unchanged. When enabled, an
	// effect check runs just before the Rego policy stage: irreversible
	// high-value actions escalate for approval, unbounded deletes are
	// blocked, and a payment to a party the same agent created earlier in
	// the session escalates. See internal/actionguard.
	actionGuardEnabled := envOr("INTENTGATE_ACTION_GUARD_ENABLED", "") == "true"
	actionGuardEscalateOverCentsRaw := envOr("INTENTGATE_ACTION_GUARD_ESCALATE_OVER_CENTS", "500000")
	actionGuardBlockUnboundedDelete := envOr("INTENTGATE_ACTION_GUARD_BLOCK_UNBOUNDED_DELETE", "true") != "false"
	// Reference verification (vendor-master check on payees). Off by default.
	// When enabled, a payment's payee is verified against the vendor master
	// loaded from INTENTGATE_REFVERIFY_CONFIG_PATH; a mismatch, unknown payee,
	// or unavailable source quarantines the call (fail-closed). See
	// internal/refverify.
	refVerifyEnabled := envOr("INTENTGATE_REFVERIFY_ENABLED", "") == "true"
	refVerifyConfigPath := envOr("INTENTGATE_REFVERIFY_CONFIG_PATH", "")
	refVerifyMinCentsRaw := envOr("INTENTGATE_REFVERIFY_MIN_CENTS", "0")
	refVerifyFailClosed := envOr("INTENTGATE_REFVERIFY_FAIL_CLOSED", "true") != "false"
	// Live system-of-record connector (takes precedence over the static config
	// file when set). Point INTENTGATE_REFVERIFY_SOR_URL at an SAP Gateway
	// OData service or any REST vendor/HR/CRM system of record. Optional auth
	// header and payee query-param name; see internal/refverify.HTTPVendorMaster.
	refVerifySORURL := envOr("INTENTGATE_REFVERIFY_SOR_URL", "")
	refVerifySORParam := envOr("INTENTGATE_REFVERIFY_SOR_PARAM", "payee")
	refVerifySORAuthHeader := envOr("INTENTGATE_REFVERIFY_SOR_AUTH_HEADER", "")
	refVerifySORAuthValue := envOr("INTENTGATE_REFVERIFY_SOR_AUTH_VALUE", "")
	refVerifySORTimeoutMs := envOr("INTENTGATE_REFVERIFY_SOR_TIMEOUT_MS", "5000")
	refVerifySORCacheTTLMs := envOr("INTENTGATE_REFVERIFY_SOR_CACHE_TTL_MS", "30000")
	// East-west (agent-to-agent) authorization. Off by default. When enabled,
	// a call to a tool named "<prefix><agent-id>" is treated as an agent-to-
	// agent call and evaluated against a zone model with default-deny. The
	// zones and allowed edges are loaded from a JSON file at
	// INTENTGATE_EASTWEST_CONFIG. See internal/eastwest.
	eastWestEnabled := envOr("INTENTGATE_EASTWEST_ENABLED", "") == "true"
	eastWestPrefix := envOr("INTENTGATE_EASTWEST_AGENT_PREFIX", "agent:")
	eastWestConfigPath := envOr("INTENTGATE_EASTWEST_CONFIG", "")
	// Per-zone north-south scope. Off by default. When enabled, an ordinary
	// tool call is checked against the caller zone's allowlist (which tools,
	// which tenants). Scopes are loaded from a JSON file at
	// INTENTGATE_ZONE_SCOPE_CONFIG. See internal/zonescope.
	// This guard decides which TOOLS a group of agents may reach, which is
	// agent-to-tool. It was named "zone scope" when groups were also the
	// agent-to-agent control; they are not any more, so the supported name is
	// TOOL_SCOPE. The ZONE_SCOPE names are still honoured for deployments that
	// already set them, and will be removed in a future major version.
	zoneScopeEnabled := envOr("INTENTGATE_TOOL_SCOPE_ENABLED", envOr("INTENTGATE_ZONE_SCOPE_ENABLED", "")) == "true"
	zoneScopeConfigPath := envOr("INTENTGATE_TOOL_SCOPE_CONFIG", envOr("INTENTGATE_ZONE_SCOPE_CONFIG", ""))
	extractorURL := envOr("INTENTGATE_EXTRACTOR_URL", "")
	policyFile := envOr("INTENTGATE_POLICY_FILE", "")
	redisURL := envOr("INTENTGATE_REDIS_URL", "")
	auditTarget := envOr("INTENTGATE_AUDIT_TARGET", "stdout")
	auditPersist := envOr("INTENTGATE_AUDIT_PERSIST", "") == "true"
	auditArgValuesRaw := envOr("INTENTGATE_AUDIT_PERSIST_ARG_VALUES", "")
	argRedaction, argRedactionErr := audit.ParseRedactionMode(auditArgValuesRaw)
	if argRedactionErr != nil {
		logger.Error("invalid INTENTGATE_AUDIT_PERSIST_ARG_VALUES", "err", argRedactionErr)
		os.Exit(1)
	}
	splunkURL := envOr("INTENTGATE_SIEM_SPLUNK_URL", "")
	splunkToken := envOr("INTENTGATE_SIEM_SPLUNK_TOKEN", "")
	splunkIndex := envOr("INTENTGATE_SIEM_SPLUNK_INDEX", "")
	datadogAPIKey := envOr("INTENTGATE_SIEM_DATADOG_API_KEY", "")
	datadogSite := envOr("INTENTGATE_SIEM_DATADOG_SITE", "")
	datadogService := envOr("INTENTGATE_SIEM_DATADOG_SERVICE", "")
	sentinelDCEURL := envOr("INTENTGATE_SIEM_SENTINEL_DCE_URL", "")
	sentinelDCRID := envOr("INTENTGATE_SIEM_SENTINEL_DCR_ID", "")
	sentinelStream := envOr("INTENTGATE_SIEM_SENTINEL_STREAM", "")
	sentinelTenantID := envOr("INTENTGATE_SIEM_SENTINEL_TENANT_ID", "")
	sentinelClientID := envOr("INTENTGATE_SIEM_SENTINEL_CLIENT_ID", "")
	sentinelClientSecret := envOr("INTENTGATE_SIEM_SENTINEL_CLIENT_SECRET", "")
	// Per-sink event routing. "findings" sends only findings (blocks,
	// escalations, step-up-flagged allows), each stamped with a
	// PagerDuty-style one-line summary; "all" sends the full raw
	// stream. Empty means "use the smart default": findings for the
	// alerting sinks when an S3 cold tier is configured, all otherwise.
	// This is the toggle that lets an operator keep the expensive hot
	// tier (Sentinel) to findings while raw logs age in S3, or send
	// everything to Sentinel when that is what they want.
	splunkEvents := envOr("INTENTGATE_SIEM_SPLUNK_EVENTS", "")
	datadogEvents := envOr("INTENTGATE_SIEM_DATADOG_EVENTS", "")
	sentinelEvents := envOr("INTENTGATE_SIEM_SENTINEL_EVENTS", "")
	// OTLP logs exporter — the lean-default, zero-new-infrastructure
	// telemetry adapter. Emits each audit event as an OTLP LogRecord to
	// the OTLP/HTTP collector the customer already runs. Endpoint alone
	// enables it; headers carry any collector/vendor auth.
	otlpEndpoint := envOr("INTENTGATE_SIEM_OTLP_ENDPOINT", "")
	otlpService := envOr("INTENTGATE_SIEM_OTLP_SERVICE", "")
	otlpNamespace := envOr("INTENTGATE_SIEM_OTLP_NAMESPACE", "")
	otlpHeadersRaw := envOr("INTENTGATE_SIEM_OTLP_HEADERS", "")
	otlpEvents := envOr("INTENTGATE_SIEM_OTLP_EVENTS", "")
	// Generic HTTPS webhook telemetry sink (Lightweight tier). Distinct
	// from INTENTGATE_WEBHOOK_URL (the console-notification fan-out); this
	// posts batched audit events as JSON to any receiver, optionally
	// HMAC-signed.
	siemWebhookURL := envOr("INTENTGATE_SIEM_WEBHOOK_URL", "")
	siemWebhookSecret := envOr("INTENTGATE_SIEM_WEBHOOK_SECRET", "")
	siemWebhookEvents := envOr("INTENTGATE_SIEM_WEBHOOK_EVENTS", "")
	// Kafka telemetry adapter (Enterprise tier). Downstream of the
	// adapter interface on the async path — opt-in, for customers who
	// already run a Kafka/Confluent/Redpanda backbone. Brokers alone
	// enable it; topic defaults to intentgate.audit.v1.
	kafkaBrokers := envOr("INTENTGATE_SIEM_KAFKA_BROKERS", "")
	kafkaTopic := envOr("INTENTGATE_SIEM_KAFKA_TOPIC", "")
	kafkaTLS := envOr("INTENTGATE_SIEM_KAFKA_TLS", "") == "true"
	kafkaSASLUser := envOr("INTENTGATE_SIEM_KAFKA_SASL_USER", "")
	kafkaSASLPass := envOr("INTENTGATE_SIEM_KAFKA_SASL_PASSWORD", "")
	kafkaEvents := envOr("INTENTGATE_SIEM_KAFKA_EVENTS", "")
	// ServiceNow GRC/SIR/ITSM adapter (configurable target). Instance URL
	// enables it; target defaults to "grc". Auth is basic (USERNAME/
	// PASSWORD) or OAuth2 client-credentials (CLIENT_ID/CLIENT_SECRET).
	snInstanceURL := envOr("INTENTGATE_SIEM_SERVICENOW_INSTANCE_URL", "")
	snTarget := envOr("INTENTGATE_SIEM_SERVICENOW_TARGET", "")
	snTable := envOr("INTENTGATE_SIEM_SERVICENOW_TABLE", "")
	snUsername := envOr("INTENTGATE_SIEM_SERVICENOW_USERNAME", "")
	snPassword := envOr("INTENTGATE_SIEM_SERVICENOW_PASSWORD", "")
	snClientID := envOr("INTENTGATE_SIEM_SERVICENOW_CLIENT_ID", "")
	snClientSecret := envOr("INTENTGATE_SIEM_SERVICENOW_CLIENT_SECRET", "")
	snMinSeverity := envOr("INTENTGATE_SIEM_SERVICENOW_MIN_SEVERITY", "")
	snIncludeAllows := envOr("INTENTGATE_SIEM_SERVICENOW_INCLUDE_ALLOWS", "") == "true"
	snCallbackBaseURL := envOr("INTENTGATE_SIEM_SERVICENOW_CALLBACK_BASE_URL", "")
	// S3 cold-storage sink. Audit events land as gzipped NDJSON in
	// a Hive-partitioned key tree (year=YYYY/month=MM/day=DD/hour=HH)
	// so Athena / Glue / Spark can prune partitions at query time
	// without an MSCK REPAIR. Credentials come from the default AWS
	// chain (IRSA / EC2 role / env vars). Bucket alone enables the
	// sink; prefix defaults to "audit/".
	s3Bucket := envOr("INTENTGATE_SIEM_S3_BUCKET", "")
	s3Prefix := envOr("INTENTGATE_SIEM_S3_PREFIX", "")
	s3Region := envOr("INTENTGATE_SIEM_S3_REGION", "")
	s3KMSKeyID := envOr("INTENTGATE_SIEM_S3_KMS_KEY_ID", "")
	s3GatewayID := envOr("INTENTGATE_SIEM_S3_GATEWAY_ID", "")
	// Endpoint override + path-style for S3-compatible stores (MinIO,
	// on-prem object stores). Leave empty for real AWS S3.
	s3Endpoint := envOr("INTENTGATE_SIEM_S3_ENDPOINT", "")
	s3ForcePathStyle := envOr("INTENTGATE_SIEM_S3_FORCE_PATH_STYLE", "") == "true"
	// Webhook fan-out (Pro v2 #3). URL is the operator-configured
	// receiver — typically a console-pro endpoint that re-routes
	// per-tenant to Slack / Teams / PagerDuty. Empty disables the
	// emitter entirely (no Pro tier check at the gateway layer;
	// console-pro gates which channels the operator can configure).
	webhookURL := envOr("INTENTGATE_WEBHOOK_URL", "")
	webhookSecret := envOr("INTENTGATE_WEBHOOK_SECRET", "")
	webhookEventsRaw := envOr("INTENTGATE_WEBHOOK_EVENTS", "")
	approvalsBackend := envOr("INTENTGATE_APPROVALS_BACKEND", "memory")
	approvalTimeoutS := envOr("INTENTGATE_APPROVAL_TIMEOUT_S", "300")
	approvalAsync := envOr("INTENTGATE_APPROVAL_ASYNC", "") == "true"
	// Policy-store backend: "off" disables the draft + promote /
	// rollback flow entirely (older deployments stay unchanged).
	// "memory" is the dev default — drafts live in-process and are
	// lost on restart, fine for kicking the tires. "postgres" is
	// the production default once a Postgres URL is configured.
	policyStoreBackend := envOr("INTENTGATE_POLICY_STORE", "off")
	tenantAdminsRaw := envOr("INTENTGATE_TENANT_ADMINS", "")
	upstreamURL := envOr("INTENTGATE_UPSTREAM_URL", "")
	upstreamTimeoutMS := envOr("INTENTGATE_UPSTREAM_TIMEOUT_MS", "")
	upstreamAuthHeader := envOr("INTENTGATE_UPSTREAM_AUTH_HEADER", "")
	upstreamToolCreds := envOr("INTENTGATE_UPSTREAM_TOOL_CREDENTIALS", "")
	credEncKeyHex := envOr("INTENTGATE_CREDENTIAL_ENCRYPTION_KEY", "")
	postgresURL := envOr("INTENTGATE_POSTGRES_URL", "")
	adminToken := envOr("INTENTGATE_ADMIN_TOKEN", "")
	metricsEnabled := envOr("INTENTGATE_METRICS_ENABLED", "") == "true"
	otelEndpoint := envOr("OTEL_EXPORTER_OTLP_ENDPOINT", "")

	masterKey, err := loadMasterKey(logger)
	if err != nil {
		logger.Error("failed to obtain master key", "err", err)
		os.Exit(1)
	}

	var extractorClient *extractor.Client
	if extractorURL != "" {
		extractorClient = extractor.New(extractorURL, 1024)
		logger.Info("intent extractor configured", "url", extractorURL)
	}

	// LLM02 PII output filter (Check 6, bidirectional). Reads from
	// INTENTGATE_PII_FILTER_ENABLED + a small set of config env vars;
	// fails-CLOSED on a bad regex (logs error + exits) rather than
	// silently booting without the filter the operator asked for.
	var piiFilter *pii.Filter
	if piiFilterEnabled {
		f, err := pii.NewFilterFromSpec(pii.FilterSpec{
			Enabled:          true,
			Patterns:         splitCSV(piiPatternsRaw),
			DefaultAction:    piiDefaultActionRaw,
			PerPatternAction: parseKVList(piiPerPatternActionRaw),
		})
		if err != nil {
			logger.Error("pii filter init failed", "err", err)
			os.Exit(1)
		}
		piiFilter = f
		logger.Info("pii filter configured",
			"enabled", true,
			"patterns", piiPatternsRaw,
			"default_action", piiDefaultActionRaw,
			"per_pattern_action", piiPerPatternActionRaw,
		)
	} else {
		logger.Info("pii filter not configured (set INTENTGATE_PII_FILTER_ENABLED=true to enable)")
	}

	// LLM05 output-schema registry. Fail-CLOSED on parse error: if the
	// operator pointed us at a config they intended to enforce but the
	// file is malformed, we refuse to boot rather than silently leave
	// the check off.
	var outputSchemas *outputschema.Registry
	if outputSchemasPath != "" {
		defaultAct, err := outputschema.ParseAction(outputSchemasDefaultAction)
		if err != nil {
			logger.Error("invalid INTENTGATE_OUTPUT_SCHEMA_DEFAULT_ACTION", "err", err)
			os.Exit(1)
		}
		raw, err := os.ReadFile(outputSchemasPath)
		if err != nil {
			logger.Error("read INTENTGATE_OUTPUT_SCHEMAS_PATH", "path", outputSchemasPath, "err", err)
			os.Exit(1)
		}
		reg := outputschema.NewRegistry(defaultAct)
		if err := reg.LoadJSON(raw); err != nil {
			logger.Error("output schema registry load failed", "path", outputSchemasPath, "err", err)
			os.Exit(1)
		}
		outputSchemas = reg
		logger.Info("output schema registry configured",
			"path", outputSchemasPath,
			"tools", reg.ToolNames(),
			"default_action", defaultAct,
		)
	} else {
		logger.Info("output schema registry not configured (set INTENTGATE_OUTPUT_SCHEMAS_PATH to enable)")
	}

	// LLM08 tenant scope enforcer. Fail-CLOSED on parse error for the
	// same reason as the output-schema registry.
	var tenantScopeEnforcer *tenantscope.Enforcer
	if tenantScopeToolsRaw != "" {
		defaultAct, err := tenantscope.ParseAction(tenantScopeDefaultAction)
		if err != nil {
			logger.Error("invalid INTENTGATE_TENANT_SCOPE_DEFAULT_ACTION", "err", err)
			os.Exit(1)
		}
		enf := tenantscope.NewEnforcer(defaultAct)
		if err := enf.LoadFromCSV(tenantScopeToolsRaw); err != nil {
			logger.Error("tenant scope load failed", "err", err)
			os.Exit(1)
		}
		tenantScopeEnforcer = enf
		logger.Info("tenant scope enforcer configured",
			"tools", enf.Tools(),
			"default_action", defaultAct,
		)
	} else {
		logger.Info("tenant scope enforcer not configured (set INTENTGATE_TENANT_SCOPED_TOOLS to enable)")
	}

	// AGENT08 fault-isolation isolator. Fail-CLOSED on parse error
	// (an operator typo on a tuning knob shouldn't silently revert
	// to wide-open).
	var faultIsolator *faultisolation.Isolator
	if faultIsolationEnabled {
		mc, err := strconv.Atoi(faultIsolationMaxConcurrentRaw)
		if err != nil {
			logger.Error("invalid INTENTGATE_FAULT_ISOLATION_MAX_CONCURRENT_PER_TOOL", "err", err)
			os.Exit(1)
		}
		ft, err := strconv.Atoi(faultIsolationFailureThresholdRaw)
		if err != nil {
			logger.Error("invalid INTENTGATE_FAULT_ISOLATION_FAILURE_THRESHOLD", "err", err)
			os.Exit(1)
		}
		cd, err := strconv.Atoi(faultIsolationCooldownMSRaw)
		if err != nil {
			logger.Error("invalid INTENTGATE_FAULT_ISOLATION_COOLDOWN_MS", "err", err)
			os.Exit(1)
		}
		faultIsolator = faultisolation.New(faultisolation.Config{
			MaxConcurrentPerTool: mc,
			FailureThreshold:     ft,
			Cooldown:             time.Duration(cd) * time.Millisecond,
		})
		logger.Info("fault isolation enabled",
			"max_concurrent_per_tool", mc,
			"failure_threshold", ft,
			"cooldown_ms", cd,
		)
	} else {
		logger.Info("fault isolation not configured (set INTENTGATE_FAULT_ISOLATION_ENABLED=true to enable)")
	}

	var actionGuard *actionguard.Guard
	if actionGuardEnabled {
		escalateOverCents, err := strconv.ParseInt(actionGuardEscalateOverCentsRaw, 10, 64)
		if err != nil {
			logger.Error("invalid INTENTGATE_ACTION_GUARD_ESCALATE_OVER_CENTS", "err", err)
			os.Exit(1)
		}
		// Optional threat-intel feed of known-bad indicators, loaded from
		// INTENTGATE_ACTION_GUARD_THREATFEED_PATH. Failure to load is fatal so a
		// misconfigured feed never silently disables the control.
		var threatFeed *actionguard.ThreatFeed
		if p := envOr("INTENTGATE_ACTION_GUARD_THREATFEED_PATH", ""); p != "" {
			threatFeed, err = actionguard.LoadThreatFeedFile(p)
			if err != nil {
				logger.Error("cannot load INTENTGATE_ACTION_GUARD_THREATFEED_PATH", "path", p, "err", err)
				os.Exit(1)
			}
		}
		actionGuard = actionguard.New(actionguard.Config{
			EscalateOverCents:    escalateOverCents,
			BlockUnboundedDelete: actionGuardBlockUnboundedDelete,
			Feed:                 threatFeed,
		})
		logger.Info("action guard enabled",
			"escalate_over_cents", escalateOverCents,
			"block_unbounded_delete", actionGuardBlockUnboundedDelete,
			"threat_feed_loaded", threatFeed != nil,
		)
	} else {
		logger.Info("action guard not configured (set INTENTGATE_ACTION_GUARD_ENABLED=true to enable)")
	}

	var refVerify *refverify.Verifier
	if refVerifyEnabled {
		refVerifyMinCents, err := strconv.ParseInt(refVerifyMinCentsRaw, 10, 64)
		if err != nil {
			logger.Error("invalid INTENTGATE_REFVERIFY_MIN_CENTS", "err", err)
			os.Exit(1)
		}
		var master refverify.VendorMaster
		masterSource := "none"
		if refVerifySORURL != "" {
			// Live system-of-record connector takes precedence.
			timeoutMs, err := strconv.ParseInt(refVerifySORTimeoutMs, 10, 64)
			if err != nil {
				logger.Error("invalid INTENTGATE_REFVERIFY_SOR_TIMEOUT_MS", "err", err)
				os.Exit(1)
			}
			cacheTTLMs, err := strconv.ParseInt(refVerifySORCacheTTLMs, 10, 64)
			if err != nil {
				logger.Error("invalid INTENTGATE_REFVERIFY_SOR_CACHE_TTL_MS", "err", err)
				os.Exit(1)
			}
			headers := map[string]string{}
			if refVerifySORAuthHeader != "" && refVerifySORAuthValue != "" {
				headers[refVerifySORAuthHeader] = refVerifySORAuthValue
			}
			master = refverify.NewHTTPVendorMaster(refverify.HTTPConfig{
				Endpoint: refVerifySORURL,
				Param:    refVerifySORParam,
				Headers:  headers,
				Timeout:  time.Duration(timeoutMs) * time.Millisecond,
				CacheTTL: time.Duration(cacheTTLMs) * time.Millisecond,
			})
			masterSource = "http_system_of_record"
		} else if refVerifyConfigPath != "" {
			records, err := refverify.LoadConfigFile(refVerifyConfigPath)
			if err != nil {
				// Fail-closed: keep the verifier enabled with a nil master so
				// payments quarantine rather than silently pass while the
				// vendor master is misconfigured.
				logger.Error("cannot load INTENTGATE_REFVERIFY_CONFIG_PATH; reference verification will fail-closed",
					"path", refVerifyConfigPath, "err", err)
			} else {
				master = refverify.NewStaticVendorMaster(records)
				masterSource = "static_config_file"
			}
		}
		refVerify = refverify.New(refverify.Config{
			Master:     master,
			MinCents:   refVerifyMinCents,
			FailClosed: refVerifyFailClosed,
		})
		logger.Info("reference verification enabled",
			"master_source", masterSource,
			"sor_url", refVerifySORURL,
			"config_path", refVerifyConfigPath,
			"min_cents", refVerifyMinCents,
			"fail_closed", refVerifyFailClosed,
			"master_loaded", master != nil,
		)
	} else {
		logger.Info("reference verification not configured (set INTENTGATE_REFVERIFY_ENABLED=true to enable)")
	}

	var eastWest *eastwest.Guard
	if eastWestEnabled {
		ewCfg := eastwest.Config{AgentToolPrefix: eastWestPrefix}
		if eastWestConfigPath != "" {
			raw, err := os.ReadFile(eastWestConfigPath)
			if err != nil {
				logger.Error("cannot read INTENTGATE_EASTWEST_CONFIG", "path", eastWestConfigPath, "err", err)
				os.Exit(1)
			}
			var fileCfg struct {
				AgentToolPrefix string `json:"agent_tool_prefix"`
				// A label attached to a set of agents. "group" is the name the
				// product uses: it is a convenience for writing one rule
				// instead of many, and it is not a boundary. "zones" is the
				// original spelling and is still read so existing configs keep
				// working; it will be dropped in a future major version.
				Groups         map[string]string `json:"groups"`
				Zones          map[string]string `json:"zones"`
				AllowIntraGrp  bool              `json:"allow_intra_group"`
				AllowIntraZone bool              `json:"allow_intra_zone"`
				// Rules written against group labels rather than agent ids.
				AllowedGroupCalls [][2]string `json:"allowed_group_calls"`
				AllowedEdges      [][2]string `json:"allowed_edges"`
				// The primary rule form: caller agent -> callee agent, either
				// side optionally a trailing-* pattern. Read both spellings so
				// a config can say what it means.
				AllowedPairs  [][2]string `json:"allowed_pairs"`
				AllowedAgents [][2]string `json:"allowed_agent_calls"`
				// The same permission carried as a governed record: purpose,
				// owner, approval, expiry, review date. Evaluated alongside
				// AllowedPairs, so a config may use either form or both. The
				// expiry here is enforced, not decorative, which is the reason
				// this has to be parsed rather than tolerated: a rules block
				// the loader ignored would leave the console showing
				// permissions the gateway was not applying.
				Rules       []eastwest.Rule `json:"rules"`
				ObserveOnly bool            `json:"observe_only"`
			}
			if err := json.Unmarshal(raw, &fileCfg); err != nil {
				logger.Error("invalid INTENTGATE_EASTWEST_CONFIG JSON", "err", err)
				os.Exit(1)
			}
			if fileCfg.AgentToolPrefix != "" {
				ewCfg.AgentToolPrefix = fileCfg.AgentToolPrefix
			}
			// New spelling wins where both are present, so a config being
			// migrated can carry the old key without silently overriding the
			// new one.
			ewCfg.AllowIntraZone = fileCfg.AllowIntraZone || fileCfg.AllowIntraGrp
			ewCfg.Zones = fileCfg.Groups
			if len(ewCfg.Zones) == 0 {
				ewCfg.Zones = fileCfg.Zones
			}
			if len(fileCfg.AllowedGroupCalls) > 0 {
				fileCfg.AllowedEdges = append(fileCfg.AllowedEdges, fileCfg.AllowedGroupCalls...)
			}
			ewCfg.AllowedEdges = fileCfg.AllowedEdges
			ewCfg.AllowedPairs = append(fileCfg.AllowedPairs, fileCfg.AllowedAgents...)
			ewCfg.Rules = fileCfg.Rules
			ewCfg.ObserveOnly = fileCfg.ObserveOnly
		}
		eastWest = eastwest.New(ewCfg)
		logger.Info("east-west authorization enabled",
			"agent_tool_prefix", ewCfg.AgentToolPrefix,
			"agent_rules", len(ewCfg.AllowedPairs),
			"governed_rules", len(ewCfg.Rules),
			"labels", len(ewCfg.Zones),
			"label_rules", len(ewCfg.AllowedEdges),
			"allow_intra_label", ewCfg.AllowIntraZone,
			"observe_only", ewCfg.ObserveOnly)
		if ewCfg.ObserveOnly {
			logger.Warn("east-west is in OBSERVE MODE: agent-to-agent calls are NOT being blocked",
				"effect", "every call is allowed and recorded as would-be-denied",
				"purpose", "collect the paths your agents need, then adopt the recommendation and turn this off",
				"hint", "set observe_only:false to enforce")
		}
		if ewCfg.AllowIntraZone {
			logger.Warn("allow_intra_group is on: agents sharing a label can call each other with no rule naming the pair",
				"hint", "prefer explicit rules in allowed_pairs, using a trailing-* pattern for a fleet")
		}
	} else {
		logger.Info("east-west authorization not configured (set INTENTGATE_EASTWEST_ENABLED=true to enable)")
	}

	var zoneScope *zonescope.Guard
	if zoneScopeEnabled {
		zsCfg := zonescope.Config{}
		if zoneScopeConfigPath != "" {
			raw, err := os.ReadFile(zoneScopeConfigPath)
			if err != nil {
				logger.Error("cannot read tool-scope config", "path", zoneScopeConfigPath, "err", err)
				os.Exit(1)
			}
			var fileCfg struct {
				Scopes map[string]struct {
					Tools   []string `json:"tools"`
					Tenants []string `json:"tenants"`
				} `json:"scopes"`
			}
			if err := json.Unmarshal(raw, &fileCfg); err != nil {
				logger.Error("invalid tool-scope config JSON", "err", err)
				os.Exit(1)
			}
			zsCfg.Scopes = make(map[string]zonescope.Scope, len(fileCfg.Scopes))
			for zone, s := range fileCfg.Scopes {
				zsCfg.Scopes[zone] = zonescope.Scope{Tools: s.Tools, Tenants: s.Tenants}
			}
		}
		zoneScope = zonescope.New(zsCfg)
		logger.Info("tool scope enabled", "scoped_groups", len(zsCfg.Scopes))
	} else {
		logger.Info("tool scope not configured (set INTENTGATE_TOOL_SCOPE_ENABLED=true to enable)")
	}

	policyEngine, policySource, err := loadPolicyEngine(logger, policyFile)
	if err != nil {
		logger.Error("failed to load policy", "err", err)
		os.Exit(1)
	}
	// Wrap the initial engine in a Reloader so promote / rollback
	// can swap it at runtime. Static deployments that never promote
	// pay nothing for the indirection (atomic-pointer load per
	// request is single-digit nanoseconds).
	policyReloader := policy.NewReloader(policyEngine)

	budgetStore, budgetSource, err := loadBudgetStore(logger, redisURL)
	if err != nil {
		logger.Error("failed to initialize budget store", "err", err)
		os.Exit(1)
	}

	auditEmitter, auditDesc, err := audit.FromTarget(auditTarget)
	if err != nil {
		logger.Error("invalid INTENTGATE_AUDIT_TARGET", "err", err)
		os.Exit(1)
	}

	// Optional Postgres-backed audit persistence. Layered as a fan-out
	// on top of whatever auditTarget produced so existing stdout-only
	// deployments keep their log-shipper pipelines unchanged.
	auditStore, auditStoreEmitter, auditStoreDesc, err := loadAuditStore(
		context.Background(), logger, postgresURL, auditPersist,
	)
	if err != nil {
		logger.Error("failed to initialize audit store", "err", err)
		os.Exit(1)
	}
	if auditStoreEmitter != nil {
		auditEmitter = audit.NewFanOut(auditEmitter, auditStoreEmitter)
		auditDesc = auditDesc + "+" + auditStoreDesc
	}

	// Response capture. Off unless explicitly configured; a nil store keeps
	// the handler's capture path inert whatever the policy says.
	payloadStore, payloadPolicy, err := loadPayloadCapture(
		context.Background(), logger, postgresURL,
	)
	if err != nil {
		logger.Error("failed to initialize response capture", "err", err)
		os.Exit(1)
	}
	startPayloadPurge(context.Background(), logger, payloadStore)

	siemEmitters, siemReporters, siemDesc, err := loadSIEM(logger, siemEnv{
		splunkURL:            splunkURL,
		splunkToken:          splunkToken,
		splunkIndex:          splunkIndex,
		datadogAPIKey:        datadogAPIKey,
		datadogSite:          datadogSite,
		datadogService:       datadogService,
		sentinelDCEURL:       sentinelDCEURL,
		sentinelDCRID:        sentinelDCRID,
		sentinelStream:       sentinelStream,
		sentinelTenantID:     sentinelTenantID,
		sentinelClientID:     sentinelClientID,
		sentinelClientSecret: sentinelClientSecret,
		s3Bucket:             s3Bucket,
		s3Prefix:             s3Prefix,
		s3Region:             s3Region,
		s3KMSKeyID:           s3KMSKeyID,
		s3GatewayID:          s3GatewayID,
		s3Endpoint:           s3Endpoint,
		s3ForcePathStyle:     s3ForcePathStyle,
		splunkEvents:         splunkEvents,
		datadogEvents:        datadogEvents,
		sentinelEvents:       sentinelEvents,
		otlpEndpoint:         otlpEndpoint,
		otlpService:          otlpService,
		otlpNamespace:        otlpNamespace,
		otlpHeadersRaw:       otlpHeadersRaw,
		otlpEvents:           otlpEvents,
		siemWebhookURL:       siemWebhookURL,
		siemWebhookSecret:    siemWebhookSecret,
		siemWebhookEvents:    siemWebhookEvents,
		snInstanceURL:        snInstanceURL,
		snTarget:             snTarget,
		snTable:              snTable,
		snUsername:           snUsername,
		snPassword:           snPassword,
		snClientID:           snClientID,
		snClientSecret:       snClientSecret,
		snMinSeverity:        snMinSeverity,
		snIncludeAllows:      snIncludeAllows,
		snCallbackBaseURL:    snCallbackBaseURL,
		kafkaBrokers:         kafkaBrokers,
		kafkaTopic:           kafkaTopic,
		kafkaTLS:             kafkaTLS,
		kafkaSASLUser:        kafkaSASLUser,
		kafkaSASLPass:        kafkaSASLPass,
		kafkaEvents:          kafkaEvents,
	})
	if err != nil {
		logger.Error("failed to initialize SIEM emitters", "err", err)
		os.Exit(1)
	}
	if len(siemEmitters) > 0 {
		all := []audit.Emitter{auditEmitter}
		for _, e := range siemEmitters {
			all = append(all, e)
		}
		auditEmitter = audit.NewFanOut(all...)
		auditDesc = auditDesc + "+" + siemDesc
	}

	// Webhook emitter (Pro v2 #3). Peer of the SIEM emitters in the
	// fan-out: same Emit-must-not-block contract, separate buffer
	// and worker, dropped events surface as counters on the admin
	// /v1/admin/integrations response.
	webhookEmitter, webhookDesc, err := loadWebhook(logger, webhookURL, webhookSecret, webhookEventsRaw)
	if err != nil {
		logger.Error("failed to initialize webhook emitter", "err", err)
		os.Exit(1)
	}
	if webhookEmitter != nil {
		auditEmitter = audit.NewFanOut(auditEmitter, webhookEmitter)
		auditDesc = auditDesc + "+" + webhookDesc
	}

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Drain SIEM emitters first so any tail-end events make it
		// to Splunk / Datadog before the process exits.
		for _, e := range siemEmitters {
			if s, ok := e.(siem.Stoppable); ok {
				_ = s.Stop(shutdownCtx)
			}
		}
		if webhookEmitter != nil {
			_ = webhookEmitter.Stop(shutdownCtx)
		}
		if auditStoreEmitter != nil {
			_ = auditStoreEmitter.Stop(shutdownCtx)
		}
		if auditStore != nil {
			_ = auditStore.Close()
		}
	}()

	credStore, err := loadCredentials(context.Background(), logger, upstreamToolCreds, postgresURL, credEncKeyHex, masterKey)
	if err != nil {
		logger.Error("failed to configure per-tool credentials", "err", err)
		os.Exit(1)
	}
	defer credStore.Close()

	upstreamClient, upstreamDesc, err := loadUpstream(logger, upstreamURL, upstreamTimeoutMS, upstreamAuthHeader)
	if err != nil {
		logger.Error("failed to configure upstream", "err", err)
		os.Exit(1)
	}

	revocationStore, revocationDesc, err := loadRevocation(context.Background(), logger, postgresURL)
	if err != nil {
		logger.Error("failed to initialize revocation store", "err", err)
		os.Exit(1)
	}

	killSwitchStore, killSwitchDesc, err := loadKillSwitch(context.Background(), logger, postgresURL)
	if err != nil {
		logger.Error("failed to initialize kill switch store", "err", err)
		os.Exit(1)
	}
	_ = killSwitchDesc

	taskBinder, taskStore, taskDesc, err := loadTaskBinder(context.Background(), logger, postgresURL)
	if err != nil {
		logger.Error("failed to initialize task binder", "err", err)
		os.Exit(1)
	}
	_ = taskDesc

	approvalsStore, approvalsDesc, err := loadApprovals(context.Background(), logger, approvalsBackend, postgresURL)
	if err != nil {
		logger.Error("failed to initialize approvals store", "err", err)
		os.Exit(1)
	}
	defer func() {
		if approvalsStore != nil {
			_ = approvalsStore.Close()
		}
	}()

	approvalTimeout, err := parseApprovalTimeout(approvalTimeoutS)
	if err != nil {
		logger.Error("INTENTGATE_APPROVAL_TIMEOUT_S invalid", "err", err)
		os.Exit(1)
	}

	policyStore, policyStoreDesc, err := loadPolicyStore(context.Background(), logger, policyStoreBackend, postgresURL)
	if err != nil {
		logger.Error("failed to initialize policy store", "err", err)
		os.Exit(1)
	}
	defer func() {
		if policyStore != nil {
			_ = policyStore.Close()
		}
	}()

	// On startup, if the policy store already has a promoted draft,
	// load its source and swap the reloader to it BEFORE the server
	// starts taking traffic. This makes promotions survive gateway
	// restarts — otherwise a pod recycle would silently fall back to
	// the embedded default / INTENTGATE_POLICY_FILE policy.
	startupPolicySource, err := reloadActivePolicy(context.Background(), logger, policyStore, policyReloader, policySource)
	if err != nil {
		logger.Error("failed to load active policy from store", "err", err)
		os.Exit(1)
	}

	// Cross-replica policy refresh. Subscribe to active-pointer
	// changes so a promote / rollback on a sibling replica swaps
	// THIS replica's compiled engine in near-real-time, instead of
	// only on pod restart. No-op when policyStore is nil.
	//
	// Seed the watcher with the per-tenant current draft ids so
	// its first polling-fallback delivery (which always fires
	// within pollFallbackInterval of start) doesn't log a
	// misleading "swapped from sibling replica" line for state
	// this pod already loaded at startup.
	startupDraftIDs := make(map[string]string)
	if policyStore != nil {
		if rows, lErr := policyStore.ListActive(context.Background()); lErr == nil {
			for _, a := range rows {
				if a.CurrentDraftID != "" {
					startupDraftIDs[a.Tenant] = a.CurrentDraftID
				}
			}
		}
	}
	watchCtx, cancelWatch := context.WithCancel(context.Background())
	defer cancelWatch()
	if policyStore != nil {
		go watchAndReloadPolicy(watchCtx, logger, policyStore, policyReloader, startupDraftIDs)
	}
	// Refresh per-tool credentials from Postgres on a timer so a change
	// made via the console on one replica propagates to the others.
	if credStore != nil {
		go func() {
			t := time.NewTicker(20 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-watchCtx.Done():
					return
				case <-t.C:
					if rErr := credStore.Reload(watchCtx); rErr != nil {
						logger.Warn("per-tool credential reload failed", "err", rErr)
					}
				}
			}
		}()
	}

	adminTokenDesc := "disabled"
	if adminToken != "" {
		adminTokenDesc = "configured"
	}

	tenantAdmins, err := parseTenantAdmins(tenantAdminsRaw)
	if err != nil {
		logger.Error("INTENTGATE_TENANT_ADMINS invalid", "err", err)
		os.Exit(1)
	}
	tenantAdminsDesc := "none"
	if n := len(tenantAdmins); n > 0 {
		tenantAdminsDesc = fmt.Sprintf("%d tenant(s)", n)
	}

	metricsHandle := metrics.New(metrics.Config{IncludeRuntimeMetrics: metricsEnabled})

	otelShutdown, otelDesc, err := loadTracing(context.Background(), version, otelEndpoint)
	if err != nil {
		logger.Error("failed to initialize OTel tracing", "err", err)
		os.Exit(1)
	}
	defer func() {
		if otelShutdown != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = otelShutdown(ctx)
		}
	}()

	logger.Info("intentgate gateway starting",
		"addr", addr,
		"version", version,
		"require_capability", requireCap,
		"require_intent", requireIntent,
		"require_budget", requireBudget,
		"intent_extractor", extractorURL != "",
		"policy_source", policySource,
		"budget_store", budgetSource,
		"audit_target", auditDesc,
		"upstream", upstreamDesc,
		"revocation_store", revocationDesc,
		"admin_api", adminTokenDesc,
		"tenant_admins", tenantAdminsDesc,
		"approvals", approvalsDesc,
		"policy_store", policyStoreDesc,
		"metrics_endpoint", metricsEnabled,
		"otel_tracing", otelDesc,
		"action_guard", actionGuardEnabled,
		"east_west", eastWestEnabled,
		"zone_scope", zoneScopeEnabled,
	)

	// Deception: inline decoy engagement detector. Decoys come from a static
	// JSON file at INTENTGATE_DECEPTION_CONFIG_PATH and/or a live sync from the
	// console decoy store at INTENTGATE_DECEPTION_SYNC_URL. The file set seeds
	// the detector so it is armed from the first request; when a sync URL is
	// set, the active set is refreshed from the console and hot-swapped, so
	// activating a decoy in the console arms the gateway within one interval.
	// A failed sync keeps the last-known-good set, so the detector never falls
	// open. Neither variable set leaves the detector nil and the stage a no-op.
	var deceptionDetector *deception.Detector
	var seedDecoys []deception.Decoy
	if p := os.Getenv("INTENTGATE_DECEPTION_CONFIG_PATH"); p != "" {
		ds, err := deception.LoadConfigFile(p)
		if err != nil {
			logger.Error("cannot load INTENTGATE_DECEPTION_CONFIG_PATH; file set skipped",
				"path", p, "err", err)
		} else {
			seedDecoys = ds
			logger.Info("deception file set loaded", "config_path", p, "decoys", len(ds))
		}
	}
	if syncURL := os.Getenv("INTENTGATE_DECEPTION_SYNC_URL"); syncURL != "" {
		sr := deception.NewSyncRegistry(seedDecoys)
		deceptionDetector = deception.New(sr)
		interval := 15 * time.Second
		if v := os.Getenv("INTENTGATE_DECEPTION_SYNC_INTERVAL_S"); v != "" {
			if n, convErr := strconv.Atoi(v); convErr == nil && n > 0 {
				interval = time.Duration(n) * time.Second
			}
		}
		syncToken := os.Getenv("INTENTGATE_DECEPTION_TOKEN")
		go sr.RunSync(watchCtx, http.DefaultClient, syncURL, syncToken, interval,
			func(n int) { logger.Info("deception decoys synced from console", "url", syncURL, "decoys", n) },
			func(syncErr error) {
				logger.Warn("deception decoy sync failed; keeping last-known-good set", "err", syncErr)
			},
		)
		logger.Info("deception live sync enabled",
			"url", syncURL, "interval_s", int(interval/time.Second), "seed_decoys", len(seedDecoys))
	} else if seedDecoys != nil {
		deceptionDetector = deception.New(deception.NewStaticRegistry(seedDecoys))
		logger.Info("deception enabled", "decoys", len(seedDecoys))
	} else {
		logger.Info("deception not configured (set INTENTGATE_DECEPTION_CONFIG_PATH or INTENTGATE_DECEPTION_SYNC_URL to enable)")
	}

	// Optional: mirror trips to the console Monitor. Best-effort; trips are
	// recorded in the gateway audit regardless. Reuses the deception token.
	var deceptionReporter deception.Reporter
	var engagementReporter deception.EngagementReporter
	if hr := deception.NewHTTPReporter(
		os.Getenv("INTENTGATE_DECEPTION_TRIP_URL"),
		os.Getenv("INTENTGATE_DECEPTION_ENGAGEMENT_URL"),
		os.Getenv("INTENTGATE_DECEPTION_TOKEN"),
	); hr != nil {
		deceptionReporter = hr
		engagementReporter = hr
		logger.Info("deception trip mirroring enabled",
			"url", os.Getenv("INTENTGATE_DECEPTION_TRIP_URL"),
			"engagement_url", os.Getenv("INTENTGATE_DECEPTION_ENGAGEMENT_URL"))
	}

	// Optional: FEDERATION data-plane push. When a control-plane URL, token, and
	// node id are configured, this node periodically rolls its local decision
	// activity up into an aggregate, zero-payload telemetry record and pushes it
	// OUTBOUND ONLY to the control plane. Customer payloads and data never leave
	// the local boundary: the rollup carries decision counts, cardinalities, a
	// check-name breakdown, and an opaque window digest only (see
	// internal/federation). A push failure is logged and never affects a local
	// decision, which has already been made and audited by the time a rollup is
	// built. The control plane pushes policy DOWN over its own path; this loop is
	// telemetry UP only.
	fedReporter := federation.NewReporter(
		envOr("INTENTGATE_FEDERATION_CONTROL_URL", ""),
		envOr("INTENTGATE_FEDERATION_TOKEN", ""),
	)
	// Air-gapped nodes cannot reach a control plane; when a rollup directory is
	// configured, each signed rollup is written there as a file for an operator
	// to carry out on media and import at the console. The push loop runs when
	// EITHER a control URL or a rollup directory is set.
	fedRollupDir := envOr("INTENTGATE_FEDERATION_ROLLUP_DIR", "")
	if fedReporter.Enabled() || fedRollupDir != "" {
		nodeID := envOr("INTENTGATE_NODE_ID", "")
		fedTenant := envOr("INTENTGATE_FEDERATION_TENANT", "")
		// Dedicated per-node signing key, established at node join. It is
		// deliberately NOT the capability master key: the control plane holds
		// this to verify rollup integrity but must never hold the key that mints
		// tokens. When unset, rollups are pushed unsigned and the control plane
		// records them as unverified -- signing is a hardening layer, not a gate.
		// For an air-gapped node the signing key is what makes an imported file
		// trustworthy, so a rollup directory should always be paired with one.
		fedSigningKey := []byte(envOr("INTENTGATE_FEDERATION_SIGNING_KEY", ""))
		fedInterval := 60 * time.Second
		if v := envOr("INTENTGATE_FEDERATION_INTERVAL_S", ""); v != "" {
			if n, convErr := strconv.Atoi(v); convErr == nil && n > 0 {
				fedInterval = time.Duration(n) * time.Second
			}
		}
		switch {
		case nodeID == "":
			logger.Error("federation enabled but INTENTGATE_NODE_ID is empty; federation push disabled")
		case auditStore == nil:
			logger.Error("federation enabled but no audit store configured; federation push disabled")
		default:
			go runFederationPush(watchCtx, logger, fedReporter, fedRollupDir, auditStore, fedSigningKey, nodeID, fedTenant, fedInterval)
			logger.Info("federation push enabled",
				"node_id", nodeID, "tenant", fedTenant,
				"url", envOr("INTENTGATE_FEDERATION_CONTROL_URL", ""),
				"rollup_dir", fedRollupDir,
				"air_gapped", !fedReporter.Enabled() && fedRollupDir != "",
				"signed", len(fedSigningKey) > 0,
				"interval_s", int(fedInterval/time.Second))
		}
	}

	// Optional: FEDERATION directive poll (policy DOWN). The control plane can
	// broadcast a global "STOP ALL AGENTS" -- or a per-domain stop -- from one
	// console across every environment. This node polls for its directive over
	// the same outbound path it opens itself; when the directive says stop it
	// engages its LOCAL kill switch, when it clears it releases the kill it set.
	// A signed directive is verified against the node signing key; an unsigned
	// or mis-signed command is ignored (fail safe). A fetch failure keeps the
	// current state -- losing the control plane never silently releases a stop.
	if durl := envOr("INTENTGATE_FEDERATION_DIRECTIVE_URL", ""); durl != "" {
		dToken := envOr("INTENTGATE_FEDERATION_TOKEN", "")
		dKey := []byte(envOr("INTENTGATE_FEDERATION_SIGNING_KEY", ""))
		dNode := envOr("INTENTGATE_NODE_ID", "")
		dInterval := 15 * time.Second
		if v := envOr("INTENTGATE_FEDERATION_DIRECTIVE_INTERVAL_S", ""); v != "" {
			if n, convErr := strconv.Atoi(v); convErr == nil && n > 0 {
				dInterval = time.Duration(n) * time.Second
			}
		}
		switch {
		case dToken == "":
			logger.Error("federation directive url set but INTENTGATE_FEDERATION_TOKEN is empty; directive poll disabled")
		case killSwitchStore == nil:
			logger.Error("federation directive url set but no kill switch configured; directive poll disabled")
		default:
			go runFederationDirectivePoll(watchCtx, logger, durl, dToken, dKey, dNode, dInterval, killSwitchStore)
			logger.Info("federation directive poll enabled",
				"url", durl, "interval_s", int(dInterval/time.Second), "signed", len(dKey) > 0)
		}
	}

	srv := server.New(server.Config{
		Addr:                  addr,
		Logger:                logger,
		Version:               version,
		MasterKey:             masterKey,
		RequireCapability:     requireCap,
		Extractor:             extractorClient,
		RequireIntent:         requireIntent,
		Policy:                policyReloader,
		Budget:                budgetStore,
		RequireBudget:         requireBudget,
		Audit:                 auditEmitter,
		AuditStore:            auditStore,
		SIEMReporters:         siemReporters,
		Upstream:              upstreamClient,
		Credentials:           credStore,
		Revocation:            revocationStore,
		KillSwitch:            killSwitchStore,
		TaskBinder:            taskBinder,
		Tasks:                 taskStore,
		Approvals:             approvalsStore,
		ApprovalTimeout:       approvalTimeout,
		ApprovalAsync:         approvalAsync,
		ArgRedaction:          argRedaction,
		ProvenanceEnabled:     provenanceEnabled,
		PIIFilter:             piiFilter,
		OutputSchemas:         outputSchemas,
		Payloads:              payloadStore,
		PayloadPolicy:         payloadPolicy,
		TenantScope:           tenantScopeEnforcer,
		FaultIsolation:        faultIsolator,
		ActionGuard:           actionGuard,
		RefVerify:             refVerify,
		Deception:             deceptionDetector,
		DeceptionReporter:     deceptionReporter,
		EngagementReporter:    engagementReporter,
		EastWest:              eastWest,
		ZoneScope:             zoneScope,
		AgentToolPrefix:       eastWestPrefix,
		EastWestConfigPath:    eastWestConfigPath,
		ZoneScopeConfigPath:   zoneScopeConfigPath,
		PolicyStore:           policyStore,
		PolicyReloader:        policyReloader,
		PolicySource:          startupPolicySource,
		RequirePolicyApproval: requirePolicyApproval,
		TenantAdmins:          tenantAdmins,
		AdminToken:            adminToken,
		Metrics:               metricsHandle,
		EnableMetricsEndpoint: metricsEnabled,
		EnableOTelTracing:     otelEndpoint != "",
	})

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		logger.Error("server failed to start", "err", err)
		os.Exit(1)
	case sig := <-sigCh:
		logger.Info("shutdown signal received", "signal", sig.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
	logger.Info("intentgate gateway stopped cleanly")
}

// loadMasterKey returns the master HMAC key for capability tokens.
//
// If INTENTGATE_MASTER_KEY is set, it is base64-decoded and returned.
// If unset, a fresh 32-byte key is generated, logged as a warning along
// with its base64url encoding, and returned. Tokens minted under an
// ephemeral key won't verify after a gateway restart — this is the
// intended dev-mode behavior; production deployments must set the env
// var to a stable value.
func loadMasterKey(logger *slog.Logger) ([]byte, error) {
	if s, ok := os.LookupEnv("INTENTGATE_MASTER_KEY"); ok && s != "" {
		key, err := capability.MasterKeyFromBase64(s)
		if err != nil {
			return nil, err
		}
		logger.Info("master key loaded from INTENTGATE_MASTER_KEY", "bytes", len(key))
		return key, nil
	}
	key, err := capability.NewMasterKey()
	if err != nil {
		return nil, err
	}
	logger.Warn("INTENTGATE_MASTER_KEY not set, generated ephemeral key for this run",
		"ephemeral_key_b64", base64.RawURLEncoding.EncodeToString(key),
		"hint", "set INTENTGATE_MASTER_KEY in your environment for stable tokens",
	)
	return key, nil
}

// loadPolicyEngine constructs the OPA-backed policy engine. If policyFile
// is non-empty, the file's contents are compiled as the customer's Rego
// source. Otherwise the embedded default policy is used.
//
// The returned source-description string ("file:/path" or "embedded
// default") is logged at startup so operators can confirm which policy
// is active.
func loadPolicyEngine(logger *slog.Logger, policyFile string) (*policy.Engine, string, error) {
	source := ""
	desc := "embedded default"
	if policyFile != "" {
		raw, err := os.ReadFile(policyFile)
		if err != nil {
			return nil, "", fmt.Errorf("read %s: %w", policyFile, err)
		}
		source = string(raw)
		desc = "file:" + policyFile
	}
	eng, err := policy.NewEngine(context.Background(), source)
	if err != nil {
		return nil, "", err
	}
	logger.Info("policy engine ready", "source", desc, "bytes", len(source))
	return eng, desc, nil
}

// loadBudgetStore returns a budget.Store for the gateway. When
// redisURL is set, the store is backed by Redis (multi-replica safe);
// otherwise an in-memory store is used (single-replica, fine for dev).
//
// The Redis client is pinged at startup so a misconfigured URL fails
// fast instead of hiding behind the first request.
func loadBudgetStore(logger *slog.Logger, redisURL string) (budget.Store, string, error) {
	if redisURL == "" {
		logger.Info("budget store: in-memory (single-replica only)")
		return budget.NewMemoryStore(), "memory", nil
	}
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, "", fmt.Errorf("redis parse url: %w", err)
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, "", fmt.Errorf("redis ping: %w", err)
	}
	logger.Info("budget store: redis", "addr", opts.Addr)
	return budget.NewRedisStore(client), "redis:" + opts.Addr, nil
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

// runFederationPush periodically builds and pushes a zero-payload rollup of the
// node's recent decision activity to the control plane. It never blocks the
// request path; on any failure the window still advances so a transient
// control-plane outage self-heals on the next tick rather than backing up.
func runFederationPush(ctx context.Context, logger *slog.Logger, reporter *federation.Reporter, rollupDir string, store auditstore.Store, signingKey []byte, nodeID, tenant string, interval time.Duration) {
	windowStart := time.Now().Add(-interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			to := time.Now()
			samples, err := collectFederationSamples(ctx, store, tenant, windowStart, to)
			if err != nil {
				logger.Warn("federation rollup query failed; will retry next interval", "err", err)
				windowStart = to
				continue
			}
			agg := federation.Summarize(samples)
			digest := federation.WindowDigest(samples)
			rollup := federation.Build(nodeID, tenant, windowStart, to, agg, digest, time.Now())
			if len(signingKey) > 0 {
				if signErr := federation.Sign(&rollup, federation.RollupKeyID, signingKey); signErr != nil {
					logger.Warn("federation rollup signing failed; skipping window", "err", signErr)
					windowStart = to
					continue
				}
			}
			if reporter.Enabled() {
				if pushErr := reporter.Push(ctx, rollup); pushErr != nil {
					logger.Warn("federation rollup push failed", "err", pushErr, "samples", len(samples))
				} else {
					logger.Info("federation rollup pushed",
						"node_id", nodeID, "samples", len(samples),
						"allow", agg.Decisions.Allow, "hold", agg.Decisions.Hold, "deny", agg.Decisions.Deny)
				}
			}
			if rollupDir != "" {
				if writeErr := writeFederationRollupFile(rollupDir, nodeID, to, rollup); writeErr != nil {
					logger.Warn("federation rollup file write failed", "err", writeErr, "dir", rollupDir)
				} else {
					logger.Info("federation rollup written for offline import", "node_id", nodeID, "dir", rollupDir)
				}
			}
			windowStart = to
		}
	}
}

// writeFederationRollupFile writes a signed rollup as JSON into dir for an
// air-gapped node's operator to carry out and import at the console. The
// filename is the node id plus the window-end timestamp so files sort by time
// and never collide.
func writeFederationRollupFile(dir, nodeID string, windowEnd time.Time, rollup federation.Rollup) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(rollup, "", "  ")
	if err != nil {
		return err
	}
	safeNode := strings.ReplaceAll(nodeID, "/", "_")
	name := fmt.Sprintf("%s-%s.json", safeNode, windowEnd.UTC().Format("20060102T150405Z"))
	return os.WriteFile(filepath.Join(dir, name), body, 0o644)
}

// collectFederationSamples pages the audit store over [from, to) and reduces each
// event to a federation.Sample -- categorical keys plus the opaque id/hash
// material for the window digest, never arguments, reasons, or results. It stops
// at a hard cap so a very busy window can never exhaust memory; a capped window
// still produces an honest (if partial) rollup.
func collectFederationSamples(ctx context.Context, store auditstore.Store, tenant string, from, to time.Time) ([]federation.Sample, error) {
	const pageSize = 1000
	const hardCap = 200000
	var samples []federation.Sample
	for offset := 0; offset < hardCap; offset += pageSize {
		events, err := store.Query(ctx, auditstore.QueryFilter{
			From:   from,
			To:     to,
			Tenant: tenant,
			Limit:  pageSize,
			Offset: offset,
		})
		if err != nil {
			return nil, err
		}
		for _, e := range events {
			samples = append(samples, federation.Sample{
				Decision:   string(e.Decision),
				Check:      string(e.Check),
				Agent:      e.AgentID,
				Tool:       e.Tool,
				Session:    e.SessionID,
				EventID:    e.EventID,
				ResultHash: e.ResultSHA256,
			})
		}
		if len(events) < pageSize {
			break
		}
	}
	return samples, nil
}

// runFederationDirectivePoll polls the control plane for this node's directive
// and applies a global STOP to the LOCAL kill switch. It only manages the kill
// it set itself (fedEngaged): it will not release a kill an operator engaged
// locally. A fetch failure keeps current state -- losing the control plane must
// never silently release a stop. A signed directive is verified against the
// node signing key; an unsigned or mis-signed command is ignored (fail safe).
func runFederationDirectivePoll(ctx context.Context, logger *slog.Logger, url, token string, signingKey []byte, nodeID string, interval time.Duration, ks killswitch.Store) {
	client := &http.Client{Timeout: 10 * time.Second}
	fedEngaged := false
	poll := func() {
		d, ok, err := federation.FetchDirective(ctx, client, url, token)
		if err != nil {
			logger.Warn("federation directive poll failed; keeping current kill-switch state", "err", err)
			return
		}
		if !ok {
			// No directive configured. Absence is not an instruction to release.
			return
		}
		if d.NodeID != "" && nodeID != "" && d.NodeID != nodeID {
			logger.Warn("federation directive addressed to a different node; ignoring", "directive_node", d.NodeID)
			return
		}
		if len(signingKey) > 0 {
			if okSig, why := federation.VerifyDirective(d, signingKey); !okSig {
				logger.Warn("federation directive failed signature verification; ignoring", "reason", why)
				return
			}
		}
		switch {
		case d.Stop && !fedEngaged:
			reason := d.Reason
			if reason == "" {
				reason = "control-plane directive"
			}
			if err := ks.Engage(ctx, killswitch.Entry{Type: killswitch.ScopeGlobal, Reason: "federation: " + reason}); err != nil {
				logger.Error("federation directive: kill-switch engage failed", "err", err)
				return
			}
			fedEngaged = true
			logger.Warn("federation directive: GLOBAL KILL ENGAGED", "scope", d.Scope, "reason", d.Reason, "seq", d.Seq)
		case !d.Stop && fedEngaged:
			if err := ks.Release(ctx, killswitch.ScopeGlobal, "", ""); err != nil {
				logger.Error("federation directive: kill-switch release failed", "err", err)
				return
			}
			fedEngaged = false
			logger.Info("federation directive: global kill released", "seq", d.Seq)
		}
	}
	poll()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll()
		}
	}
}

// splitCSV parses a comma-separated env value into a trimmed string
// slice. Empty input returns nil. Used by INTENTGATE_PII_PATTERNS and
// any future env var that takes a list (e.g. URL allowlists).
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseKVList parses a comma-separated key:value list into a map.
// Used by INTENTGATE_PII_PER_PATTERN_ACTION (e.g. "iban:block,credit_card:block").
// Skips malformed entries silently — same fail-graceful posture as the
// rest of the config layer; the operator sees nothing applied rather
// than the binary refusing to boot on a single bad pair.
func parseKVList(s string) map[string]string {
	if s == "" {
		return nil
	}
	out := make(map[string]string)
	for _, kv := range strings.Split(s, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		colon := strings.IndexByte(kv, ':')
		if colon <= 0 || colon == len(kv)-1 {
			continue
		}
		k := strings.TrimSpace(kv[:colon])
		v := strings.TrimSpace(kv[colon+1:])
		if k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// loadUpstream constructs the upstream MCP client from environment.
// Returns (nil, "stub (none)", nil) when INTENTGATE_UPSTREAM_URL is
// unset — that's the dev-friendly path where the gateway returns its
// own stub allow for any call passing the four checks.
//
// When the URL is set, the timeout is read from
// INTENTGATE_UPSTREAM_TIMEOUT_MS (default 30000), the URL is validated
// at startup so a misconfigured deployment fails fast, and the
// human-readable description used in the startup log line includes the
// URL and timeout for operator visibility.
func loadUpstream(logger *slog.Logger, url, timeoutMS, authHeader string) (*upstream.Client, string, error) {
	if url == "" {
		logger.Info("upstream not configured: returning stub allow for authorized calls",
			"hint", "set INTENTGATE_UPSTREAM_URL to forward to a real MCP tool server")
		return nil, "stub (none)", nil
	}

	timeout := upstream.DefaultTimeout
	if timeoutMS != "" {
		ms, err := strconv.Atoi(timeoutMS)
		if err != nil {
			return nil, "", fmt.Errorf("INTENTGATE_UPSTREAM_TIMEOUT_MS: %w", err)
		}
		if ms <= 0 {
			return nil, "", fmt.Errorf("INTENTGATE_UPSTREAM_TIMEOUT_MS must be positive, got %d", ms)
		}
		timeout = time.Duration(ms) * time.Millisecond
	}

	// Credential brokering: INTENTGATE_UPSTREAM_AUTH_HEADER holds the
	// real tool-server credential as "Header-Name: value" (e.g.
	// "Authorization: Bearer sk-..."). The gateway injects it on every
	// forwarded call so agents authenticate to the gateway with a
	// capability token and never possess the upstream secret.
	var headers map[string]string
	brokered := ""
	if h := strings.TrimSpace(authHeader); h != "" {
		name, value, ok := strings.Cut(h, ":")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if !ok || name == "" || value == "" {
			return nil, "", fmt.Errorf(`INTENTGATE_UPSTREAM_AUTH_HEADER must be "Header-Name: value"`)
		}
		headers = map[string]string{name: value}
		brokered = ", credential brokered via " + name
		// Log the header NAME only — never the secret value.
		logger.Info("upstream credential brokering enabled", "header", name)
	}

	c, err := upstream.New(upstream.Config{URL: url, Timeout: timeout, Headers: headers})
	if err != nil {
		return nil, "", err
	}
	return c, fmt.Sprintf("%s (timeout %s%s)", url, timeout, brokered), nil
}

// loadCredentials builds the per-tool credential store from
// INTENTGATE_UPSTREAM_TOOL_CREDENTIALS — a JSON object mapping a tool
// name to its upstream credential as "Header-Name: value", e.g.
//
//	{"transfer_funds":"Authorization: Bearer sk-pay","read_invoice":"X-Api-Key: abc"}
//
// The gateway injects the matching credential per tool; tools without
// an entry fall back to the global INTENTGATE_UPSTREAM_AUTH_HEADER.
// Returns (nil, nil) when unset — per-tool brokering is simply off.
func loadCredentials(ctx context.Context, logger *slog.Logger, raw, postgresURL, encKeyHex string, masterKey []byte) (*credentials.Store, error) {
	seed := map[string]string{}
	if strings.TrimSpace(raw) != "" {
		if err := json.Unmarshal([]byte(raw), &seed); err != nil {
			return nil, fmt.Errorf(`INTENTGATE_UPSTREAM_TOOL_CREDENTIALS must be a JSON object of tool -> "Header: value": %w`, err)
		}
	}

	// Durable, console-managed store when Postgres is configured: the
	// per-tool secrets are encrypted at rest and editable at runtime via
	// the admin API (the console). Env entries seed first-boot only.
	if strings.TrimSpace(postgresURL) != "" {
		key, err := credentialEncryptionKey(encKeyHex, masterKey)
		if err != nil {
			return nil, err
		}
		db, err := credentials.NewPostgresStore(ctx, postgresURL, key)
		if err != nil {
			return nil, err
		}
		store, err := credentials.NewPostgres(ctx, db, seed)
		if err != nil {
			db.Close()
			return nil, err
		}
		logger.Info("per-tool credential brokering enabled (console-managed, encrypted in Postgres)",
			"tools", store.Tools())
		return store, nil
	}

	// In-memory, env-configured store (no Postgres): per-tool secrets
	// from INTENTGATE_UPSTREAM_TOOL_CREDENTIALS, no runtime management.
	if len(seed) == 0 {
		return nil, nil
	}
	store, err := credentials.New(seed)
	if err != nil {
		return nil, err
	}
	logger.Info("per-tool credential brokering enabled (env-configured)", "tools", store.Tools())
	return store, nil
}

// credentialEncryptionKey returns the 32-byte AES-256 key used to
// encrypt per-tool credentials at rest. Operators may set a dedicated
// INTENTGATE_CREDENTIAL_ENCRYPTION_KEY (64 hex chars); otherwise the key
// is derived from the gateway master key so it works without an extra
// secret.
func credentialEncryptionKey(hexKey string, masterKey []byte) ([]byte, error) {
	if h := strings.TrimSpace(hexKey); h != "" {
		key, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("INTENTGATE_CREDENTIAL_ENCRYPTION_KEY: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("INTENTGATE_CREDENTIAL_ENCRYPTION_KEY must be 32 bytes (64 hex chars), got %d", len(key))
		}
		return key, nil
	}
	sum := sha256.Sum256(masterKey)
	return sum[:], nil
}

// loadTracing initializes the OpenTelemetry tracer provider when an
// OTLP endpoint is configured. Returns a shutdown function the caller
// must call on graceful exit so in-flight spans flush.
//
// We deliberately don't start a sampler / metric pipeline here — the
// SDK defaults (always-on sampling, no metric pipeline) are fine for
// v1. Operators with high-RPS deployments can add their own sampler
// via standard OTEL_TRACES_SAMPLER env vars; the SDK reads them.
func loadTracing(ctx context.Context, version, endpoint string) (func(context.Context) error, string, error) {
	if endpoint == "" {
		return nil, "disabled", nil
	}

	exp, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, "", fmt.Errorf("otlp exporter: %w", err)
	}

	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName("intentgate-gateway"),
		semconv.ServiceVersion(version),
	))
	if err != nil {
		return nil, "", fmt.Errorf("otel resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	return tp.Shutdown, fmt.Sprintf("enabled (otlp grpc: %s)", endpoint), nil
}

// siemEnv groups the SIEM-related environment variables so loadSIEM
// has a small, stable signature.
type siemEnv struct {
	splunkURL            string
	splunkToken          string
	splunkIndex          string
	datadogAPIKey        string
	datadogSite          string
	datadogService       string
	sentinelDCEURL       string
	sentinelDCRID        string
	sentinelStream       string
	sentinelTenantID     string
	sentinelClientID     string
	sentinelClientSecret string
	s3Bucket             string
	s3Prefix             string
	s3Region             string
	s3KMSKeyID           string
	s3GatewayID          string
	s3Endpoint           string
	s3ForcePathStyle     bool
	// Per-sink event routing modes ("all" / "findings" / ""). Empty
	// uses the smart default computed in loadSIEM.
	splunkEvents   string
	datadogEvents  string
	sentinelEvents string
	// OTLP logs exporter (lean-default telemetry adapter). Endpoint
	// alone enables it; headersRaw is a "k=v,k2=v2" list parsed in
	// loadSIEM into request headers (typically a collector auth header).
	otlpEndpoint   string
	otlpService    string
	otlpNamespace  string
	otlpHeadersRaw string
	otlpEvents     string
	// Generic HTTPS webhook telemetry sink (Lightweight tier).
	siemWebhookURL    string
	siemWebhookSecret string
	siemWebhookEvents string
	// Kafka telemetry adapter (Enterprise tier, async downstream).
	kafkaBrokers  string
	kafkaTopic    string
	kafkaTLS      bool
	kafkaSASLUser string
	kafkaSASLPass string
	kafkaEvents   string
	// ServiceNow GRC/SIR/ITSM adapter (configurable target, async).
	snInstanceURL     string
	snTarget          string
	snTable           string
	snUsername        string
	snPassword        string
	snClientID        string
	snClientSecret    string
	snMinSeverity     string
	snIncludeAllows   bool
	snCallbackBaseURL string
}

// loadSIEM constructs whichever SIEM emitters the operator has wired
// via env vars. Returns:
//
//   - emitters    : audit.Emitter slice ready to drop into the fan-out
//   - reporters   : siem.StatusReporter slice for the admin endpoint
//   - description : human-readable summary used in the startup log
//
// A misconfigured destination (e.g. SPLUNK_URL set without
// SPLUNK_TOKEN) returns an error so the gateway fails fast instead
// of silently dropping events.
func loadSIEM(logger *slog.Logger, env siemEnv) ([]audit.Emitter, []siem.StatusReporter, string, error) {
	var emitters []audit.Emitter
	var reporters []siem.StatusReporter
	var labels []string

	// Smart default for the alerting sinks (Splunk, Datadog, Sentinel):
	// when an S3 cold tier is configured, default them to findings so
	// the expensive hot tier only holds findings while raw logs age in
	// S3; otherwise default to all so nothing is lost. Each sink's own
	// INTENTGATE_SIEM_<SINK>_EVENTS overrides this default. The S3 sink
	// is always the raw stream and is never wrapped.
	defaultMode := siem.ModeAll
	if env.s3Bucket != "" {
		defaultMode = siem.ModeFindings
	}

	if env.splunkURL != "" || env.splunkToken != "" {
		if env.splunkURL == "" || env.splunkToken == "" {
			return nil, nil, "", fmt.Errorf("INTENTGATE_SIEM_SPLUNK_URL and INTENTGATE_SIEM_SPLUNK_TOKEN must both be set")
		}
		em, err := siem.NewSplunkEmitter(siem.SplunkConfig{
			URL:    env.splunkURL,
			Token:  env.splunkToken,
			Index:  env.splunkIndex,
			Logger: logger,
		})
		if err != nil {
			return nil, nil, "", err
		}
		splunkMode := siem.ParseEventMode(env.splunkEvents, defaultMode)
		routed := siem.NewRoutingEmitter(em, splunkMode)
		emitters = append(emitters, routed)
		if sr, ok := routed.(siem.StatusReporter); ok {
			reporters = append(reporters, sr)
		} else {
			reporters = append(reporters, em)
		}
		labels = append(labels, "splunk")
		logger.Info("SIEM emitter: splunk", "url", env.splunkURL, "index", env.splunkIndex, "events", string(splunkMode))
	}

	if env.datadogAPIKey != "" {
		em, err := siem.NewDatadogEmitter(siem.DatadogConfig{
			APIKey:  env.datadogAPIKey,
			Site:    env.datadogSite,
			Service: env.datadogService,
			Logger:  logger,
		})
		if err != nil {
			return nil, nil, "", err
		}
		datadogMode := siem.ParseEventMode(env.datadogEvents, defaultMode)
		routed := siem.NewRoutingEmitter(em, datadogMode)
		emitters = append(emitters, routed)
		if sr, ok := routed.(siem.StatusReporter); ok {
			reporters = append(reporters, sr)
		} else {
			reporters = append(reporters, em)
		}
		labels = append(labels, "datadog")
		logger.Info("SIEM emitter: datadog", "site", env.datadogSite, "events", string(datadogMode))
	}

	if anySentinelSet := env.sentinelDCEURL != "" ||
		env.sentinelDCRID != "" || env.sentinelStream != "" ||
		env.sentinelTenantID != "" || env.sentinelClientID != "" ||
		env.sentinelClientSecret != ""; anySentinelSet {
		em, err := siem.NewSentinelEmitter(siem.SentinelConfig{
			DCEUrl:         env.sentinelDCEURL,
			DCRImmutableID: env.sentinelDCRID,
			StreamName:     env.sentinelStream,
			TenantID:       env.sentinelTenantID,
			ClientID:       env.sentinelClientID,
			ClientSecret:   env.sentinelClientSecret,
			Logger:         logger,
		})
		if err != nil {
			return nil, nil, "", fmt.Errorf("sentinel: %w", err)
		}
		sentinelMode := siem.ParseEventMode(env.sentinelEvents, defaultMode)
		routed := siem.NewRoutingEmitter(em, sentinelMode)
		emitters = append(emitters, routed)
		if sr, ok := routed.(siem.StatusReporter); ok {
			reporters = append(reporters, sr)
		} else {
			reporters = append(reporters, em)
		}
		labels = append(labels, "sentinel")
		logger.Info("SIEM emitter: sentinel",
			"dce", env.sentinelDCEURL,
			"dcr", env.sentinelDCRID,
			"stream", env.sentinelStream,
			"events", string(sentinelMode))
	}

	if env.otlpEndpoint != "" {
		headers := map[string]string{}
		for _, p := range splitCSV(env.otlpHeadersRaw) {
			if k, v, ok := strings.Cut(p, "="); ok {
				k = strings.TrimSpace(k)
				if k != "" {
					headers[k] = strings.TrimSpace(v)
				}
			}
		}
		em, err := siem.NewOTLPEmitter(siem.OTLPConfig{
			Endpoint:    env.otlpEndpoint,
			ServiceName: env.otlpService,
			Namespace:   env.otlpNamespace,
			Headers:     headers,
			Logger:      logger,
		})
		if err != nil {
			return nil, nil, "", fmt.Errorf("otlp: %w", err)
		}
		otlpMode := siem.ParseEventMode(env.otlpEvents, defaultMode)
		routed := siem.NewRoutingEmitter(em, otlpMode)
		emitters = append(emitters, routed)
		if sr, ok := routed.(siem.StatusReporter); ok {
			reporters = append(reporters, sr)
		} else {
			reporters = append(reporters, em)
		}
		labels = append(labels, "otlp")
		logger.Info("SIEM emitter: otlp",
			"endpoint", env.otlpEndpoint,
			"service", env.otlpService,
			"events", string(otlpMode))
	}

	if env.siemWebhookURL != "" {
		em, err := siem.NewWebhookEmitter(siem.WebhookConfig{
			URL:    env.siemWebhookURL,
			Secret: env.siemWebhookSecret,
			Logger: logger,
		})
		if err != nil {
			return nil, nil, "", fmt.Errorf("webhook: %w", err)
		}
		webhookMode := siem.ParseEventMode(env.siemWebhookEvents, defaultMode)
		routed := siem.NewRoutingEmitter(em, webhookMode)
		emitters = append(emitters, routed)
		if sr, ok := routed.(siem.StatusReporter); ok {
			reporters = append(reporters, sr)
		} else {
			reporters = append(reporters, em)
		}
		labels = append(labels, "webhook")
		logger.Info("SIEM emitter: webhook", "url", env.siemWebhookURL, "events", string(webhookMode))
	}

	if env.kafkaBrokers != "" {
		topic := env.kafkaTopic
		if topic == "" {
			topic = "intentgate.audit.v1"
		}
		em, err := siem.NewKafkaEmitter(siem.KafkaConfig{
			Brokers:  splitCSV(env.kafkaBrokers),
			Topic:    topic,
			TLS:      env.kafkaTLS,
			SASLUser: env.kafkaSASLUser,
			SASLPass: env.kafkaSASLPass,
			Logger:   logger,
		})
		if err != nil {
			return nil, nil, "", fmt.Errorf("kafka: %w", err)
		}
		kafkaMode := siem.ParseEventMode(env.kafkaEvents, defaultMode)
		routed := siem.NewRoutingEmitter(em, kafkaMode)
		emitters = append(emitters, routed)
		if sr, ok := routed.(siem.StatusReporter); ok {
			reporters = append(reporters, sr)
		} else {
			reporters = append(reporters, em)
		}
		labels = append(labels, "kafka")
		logger.Info("SIEM emitter: kafka",
			"brokers", env.kafkaBrokers,
			"topic", topic,
			"tls", env.kafkaTLS,
			"events", string(kafkaMode))
	}

	if env.snInstanceURL != "" {
		em, err := siem.NewServiceNowEmitter(siem.ServiceNowConfig{
			InstanceURL:        env.snInstanceURL,
			Target:             siem.ServiceNowTarget(strings.ToLower(strings.TrimSpace(env.snTarget))),
			Table:              env.snTable,
			Username:           env.snUsername,
			Password:           env.snPassword,
			ClientID:           env.snClientID,
			ClientSecret:       env.snClientSecret,
			MinSeverity:        env.snMinSeverity,
			IncludeAllows:      env.snIncludeAllows,
			IncludeProofHashes: true,
			CallbackBaseURL:    env.snCallbackBaseURL,
			Logger:             logger,
		})
		if err != nil {
			return nil, nil, "", fmt.Errorf("servicenow: %w", err)
		}
		// The ServiceNow adapter applies its own severity / allow gate
		// (per its config), so it is not wrapped in a RoutingEmitter.
		emitters = append(emitters, em)
		reporters = append(reporters, em)
		labels = append(labels, "servicenow")
		logger.Info("SIEM emitter: servicenow",
			"instance", env.snInstanceURL,
			"target", env.snTarget,
			"table", env.snTable,
			"include_allows", env.snIncludeAllows)
	}

	if env.s3Bucket != "" {
		em, err := siem.NewS3Emitter(siem.S3Config{
			Bucket:         env.s3Bucket,
			Prefix:         env.s3Prefix,
			Region:         env.s3Region,
			KMSKeyID:       env.s3KMSKeyID,
			GatewayID:      env.s3GatewayID,
			Endpoint:       env.s3Endpoint,
			ForcePathStyle: env.s3ForcePathStyle,
			Logger:         logger,
		})
		if err != nil {
			return nil, nil, "", fmt.Errorf("s3: %w", err)
		}
		emitters = append(emitters, em)
		reporters = append(reporters, em)
		labels = append(labels, "s3")
		logger.Info("SIEM emitter: s3",
			"bucket", env.s3Bucket,
			"prefix", env.s3Prefix,
			"region", env.s3Region)
	}

	desc := "none"
	if len(labels) > 0 {
		desc = strings.Join(labels, ",")
	}
	return emitters, reporters, desc, nil
}

// loadWebhook constructs the optional webhook emitter. Returns
// (nil, "disabled", nil) when INTENTGATE_WEBHOOK_URL is unset —
// webhook fan-out is fully opt-in. When the URL IS set, we
// validate the secret (warning when empty, since unsigned webhooks
// can be spoofed by anyone who knows the receiver URL) and parse
// the optional events allowlist.
func loadWebhook(logger *slog.Logger, url, secret, eventsRaw string) (*webhook.Emitter, string, error) {
	if strings.TrimSpace(url) == "" {
		return nil, "disabled", nil
	}
	parsedSecret, err := webhook.MustParseSecret(secret)
	if err != nil {
		return nil, "", fmt.Errorf("INTENTGATE_WEBHOOK_SECRET: %w", err)
	}
	if len(parsedSecret) == 0 {
		logger.Warn("webhook configured without a signing secret; receivers cannot verify authenticity",
			"hint", "set INTENTGATE_WEBHOOK_SECRET to a 32-byte hex string")
	}

	sink, err := webhook.NewHTTPSink(webhook.HTTPSinkConfig{
		URL:    url,
		Secret: parsedSecret,
		Logger: logger,
	})
	if err != nil {
		return nil, "", fmt.Errorf("webhook sink: %w", err)
	}

	var allowed []string
	if eventsRaw != "" {
		for _, s := range strings.Split(eventsRaw, ",") {
			if s = strings.TrimSpace(s); s != "" {
				allowed = append(allowed, s)
			}
		}
	}

	em := webhook.NewEmitter(webhook.EmitterConfig{
		Sink:   sink,
		Filter: webhook.DefaultFilter(allowed),
		Logger: logger,
	})
	logger.Info("webhook emitter configured",
		"url", url,
		"signed", len(parsedSecret) > 0,
		"events_filter", eventsRaw,
	)
	return em, "webhook", nil
}

// loadAuditStore constructs the optional Postgres-backed audit store
// and its async emitter. Returns (nil, nil, "disabled", nil) when
// audit persistence isn't enabled or no Postgres URL is configured —
// the gateway runs fine with stdout-only audit, and we don't want to
// half-enable persistence (which would silently degrade the
// /v1/admin/audit endpoint to "always empty").
func loadAuditStore(ctx context.Context, logger *slog.Logger, postgresURL string, persist bool) (auditstore.Store, *auditstore.Emitter, string, error) {
	if !persist {
		return nil, nil, "disabled", nil
	}
	if postgresURL == "" {
		// Persist=true without a DSN is operator error: a misconfigured
		// gateway will look "audit-persistent" in dashboards but lose
		// every event. Refuse to start.
		return nil, nil, "", fmt.Errorf("INTENTGATE_AUDIT_PERSIST=true requires INTENTGATE_POSTGRES_URL")
	}
	store, err := auditstore.NewPostgresStore(ctx, postgresURL)
	if err != nil {
		return nil, nil, "", err
	}
	em := auditstore.NewEmitter(auditstore.EmitterConfig{
		Store:  store,
		Logger: logger,
	})
	logger.Info("audit store: postgres", "persist", true)
	return store, em, "postgres", nil
}

// parseTenantAdmins reads INTENTGATE_TENANT_ADMINS into a map.
//
// Format: "tenant1:token1,tenant2:token2". Whitespace around each
// component is trimmed; entries with empty tenant or empty token are
// rejected at startup so a typo doesn't silently lock out an admin.
// Tokens MUST NOT contain commas (encoded if needed) or colons in
// the tenant name; the parser refuses ambiguous inputs.
func parseTenantAdmins(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	out := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		idx := strings.Index(pair, ":")
		if idx <= 0 || idx == len(pair)-1 {
			return nil, fmt.Errorf("entry %q must be in tenant:token format", pair)
		}
		tenant := strings.TrimSpace(pair[:idx])
		token := strings.TrimSpace(pair[idx+1:])
		if tenant == "" || token == "" {
			return nil, fmt.Errorf("entry %q has empty tenant or token", pair)
		}
		if _, dup := out[tenant]; dup {
			return nil, fmt.Errorf("duplicate tenant %q in TENANT_ADMINS", tenant)
		}
		out[tenant] = token
	}
	return out, nil
}

// loadApprovals constructs the human-approval queue.
//
//	backend = "off"      → returns (nil, "off", nil) — escalate becomes block.
//	backend = "memory"   → in-process queue, single replica only.
//	backend = "postgres" → durable queue at INTENTGATE_POSTGRES_URL.
//
// A misconfigured backend ("postgres" without a DSN) returns an error
// so the gateway fails fast.
func loadApprovals(ctx context.Context, logger *slog.Logger, backend, postgresURL string) (approvals.Store, string, error) {
	switch backend {
	case "off":
		logger.Info("approvals queue: disabled")
		return nil, "off", nil
	case "", "memory":
		logger.Info("approvals queue: in-memory (single-replica only, lost on restart)")
		return approvals.NewMemoryStore(), "memory", nil
	case "postgres":
		if postgresURL == "" {
			return nil, "", fmt.Errorf("INTENTGATE_APPROVALS_BACKEND=postgres requires INTENTGATE_POSTGRES_URL")
		}
		store, err := approvals.NewPostgresStore(ctx, postgresURL)
		if err != nil {
			return nil, "", err
		}
		logger.Info("approvals queue: postgres")
		return store, "postgres", nil
	default:
		return nil, "", fmt.Errorf("unknown INTENTGATE_APPROVALS_BACKEND %q (want off|memory|postgres)", backend)
	}
}

// parseApprovalTimeout converts the seconds-as-string env var into a
// duration. Empty / 0 falls back to 5 minutes; negative is rejected.
func parseApprovalTimeout(s string) (time.Duration, error) {
	if s == "" {
		return 5 * time.Minute, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("not an integer: %w", err)
	}
	if n < 0 {
		return 0, fmt.Errorf("must be >= 0, got %d", n)
	}
	if n == 0 {
		return 5 * time.Minute, nil
	}
	return time.Duration(n) * time.Second, nil
}

// loadPolicyStore constructs the optional draft + active-pointer
// store backing /v1/admin/policies/*.
//
//	backend = "off"      → returns (nil, "off", nil); draft endpoints
//	                       aren't registered. Existing deployments
//	                       upgrading to v1.4 see no change unless they
//	                       explicitly opt in.
//	backend = "memory"   → in-process MemoryStore, fine for dev / smoke.
//	backend = "postgres" → durable PostgresStore at the existing
//	                       INTENTGATE_POSTGRES_URL.
//
// Misconfiguration (postgres without a DSN) is a fail-fast.
func loadPolicyStore(ctx context.Context, logger *slog.Logger, backend, postgresURL string) (policystore.Store, string, error) {
	switch backend {
	case "", "off":
		logger.Info("policy store: disabled",
			"hint", "set INTENTGATE_POLICY_STORE=memory (dev) or postgres (prod) to enable /v1/admin/policies/*")
		return nil, "off", nil
	case "memory":
		logger.Info("policy store: in-memory (single-replica only, lost on restart)")
		return policystore.NewMemoryStore(), "memory", nil
	case "postgres":
		if postgresURL == "" {
			return nil, "", fmt.Errorf("INTENTGATE_POLICY_STORE=postgres requires INTENTGATE_POSTGRES_URL")
		}
		store, err := policystore.NewPostgresStore(ctx, postgresURL)
		if err != nil {
			return nil, "", err
		}
		logger.Info("policy store: postgres")
		return store, "postgres", nil
	default:
		return nil, "", fmt.Errorf("unknown INTENTGATE_POLICY_STORE %q (want off|memory|postgres)", backend)
	}
}

// reloadActivePolicy hydrates the policy reloader from the store
// at startup so promotions survive gateway restarts. v1.5 makes
// this per-tenant: every populated active row gets its target
// draft compiled and installed in the reloader's matching slot.
// The default-fallback row (tenant="") drives the reloader's
// default engine, preserving v1.4 single-tenant semantics for
// deployments that haven't promoted any per-tenant overlays.
//
// Returns the startup-source label fed back to the
// /v1/admin/policies/active handler so the console knows whether
// the gateway is currently running an embedded default, a file-
// supplied policy, or a promoted draft.
//
// When the store is nil (INTENTGATE_POLICY_STORE=off) we leave the
// reloader untouched and return the fallback source.
//
// When any active row's recompile fails, we log loudly and refuse
// to start: the gateway running the embedded default while the
// database says "policy X is live for tenant Y" is exactly the
// kind of confusion auditors flag, so failing fast is correct.
func reloadActivePolicy(ctx context.Context, logger *slog.Logger, store policystore.Store, reloader *policy.Reloader, fallbackSource string) (string, error) {
	if store == nil {
		return fallbackSource, nil
	}
	rows, err := store.ListActive(ctx)
	if err != nil {
		return "", fmt.Errorf("list active policies: %w", err)
	}
	// Track whether the default-fallback slot got populated from
	// the store, vs left at the startup-bootstrap engine (embedded
	// default or INTENTGATE_POLICY_FILE).
	defaultHydratedFromStore := false
	tenantsLoaded := 0

	for _, active := range rows {
		if active.CurrentDraftID == "" {
			continue
		}
		draft, err := store.GetDraft(ctx, active.CurrentDraftID)
		if err != nil {
			return "", fmt.Errorf("load active draft %q (tenant=%q): %w",
				active.CurrentDraftID, active.Tenant, err)
		}
		engine, err := policy.NewEngine(ctx, draft.RegoSource)
		if err != nil {
			return "", fmt.Errorf("compile active draft %q (tenant=%q): %w",
				active.CurrentDraftID, active.Tenant, err)
		}
		if _, err := reloader.SwapFor(active.Tenant, engine); err != nil {
			return "", fmt.Errorf("swap to active draft %q (tenant=%q): %w",
				active.CurrentDraftID, active.Tenant, err)
		}
		logger.Info("loaded promoted policy from store",
			"tenant", active.Tenant,
			"draft_id", active.CurrentDraftID,
			"name", draft.Name,
			"promoted_at", active.PromotedAt,
			"promoted_by", active.PromotedBy,
		)
		if active.Tenant == "" {
			defaultHydratedFromStore = true
		} else {
			tenantsLoaded++
		}
	}

	if tenantsLoaded > 0 {
		logger.Info("policy reloader hydrated per-tenant overlays",
			"tenants_loaded", tenantsLoaded,
			"default_from_store", defaultHydratedFromStore)
	}
	if defaultHydratedFromStore {
		return "draft", nil
	}
	if tenantsLoaded > 0 {
		// Some tenants have their own policy but the default slot
		// still uses the startup bootstrap. Label reflects that the
		// "live" answer depends on the calling tenant.
		return fallbackSource + " + per-tenant overlays", nil
	}
	logger.Info("policy store has no active drafts; using fallback policy",
		"fallback_source", fallbackSource)
	return fallbackSource, nil
}

// watchAndReloadPolicy is the cross-replica refresh loop. It
// subscribes to the policy store's Watch channel and, for every
// active-pointer change observed (either via Postgres NOTIFY from
// a sibling replica or via the polling fallback), fetches the
// referenced draft, compiles it, and Swaps the live engine.
//
// Reliability semantics:
//
//   - Idempotent. If the incoming active.CurrentDraftID matches what
//     we last loaded, the swap is skipped — no compile, no engine
//     churn. Handles both "redundant NOTIFY after a no-op promote"
//     and "polling fallback fires on an unchanged active".
//   - Compile failures DON'T crash the gateway. A draft that
//     somehow lands in the active row with broken Rego is logged
//     loudly and the in-flight engine keeps serving traffic. The
//     admin endpoint compiles on save AND on promote, so the only
//     way to get here is a manual DB poke or a deeply weird race.
//   - The loop exits when the Watch channel closes (store Close
//     during shutdown OR ctx cancelled).
//
// The startup-time [reloadActivePolicy] hydration already covers
// "what's currently active" before the server takes traffic; this
// watcher only handles changes that happen WHILE the gateway is
// running.
//
// startupDraftIDs is a per-tenant seed for the de-dup map: the
// first polling-fallback delivery for each tenant slot recognizes
// the state this pod already loaded at startup as a no-op and
// skips the re-compile + misleading "swapped from sibling" log
// line.
func watchAndReloadPolicy(ctx context.Context, logger *slog.Logger, store policystore.Store, reloader *policy.Reloader, startupDraftIDs map[string]string) {
	ch, err := store.Watch(ctx)
	if err != nil {
		logger.Error("policy watcher failed to subscribe; cross-replica refresh disabled",
			"err", err)
		return
	}
	logger.Info("policy watcher started",
		"seeded_tenants", len(startupDraftIDs))

	// Per-tenant last-applied tracking. Seeded from startup so we
	// don't re-load what reloadActivePolicy already installed.
	lastApplied := make(map[string]string, len(startupDraftIDs))
	for tenant, id := range startupDraftIDs {
		lastApplied[tenant] = id
	}

	for active := range ch {
		if active.CurrentDraftID == "" {
			// DeleteActive signal. For a per-tenant slot, drop it
			// so subsequent requests from that tenant fall back to
			// the default. For the default-fallback slot, no-op:
			// clearing the default would leave the gateway with
			// nothing to serve — the store's DeleteActive enforces
			// that on the write path too, but defense-in-depth.
			if active.Tenant != "" {
				reloader.RemoveFor(active.Tenant)
				delete(lastApplied, active.Tenant)
				logger.Info("policy watcher: tenant slot cleared from sibling replica",
					"tenant", active.Tenant)
			}
			continue
		}
		if active.CurrentDraftID == lastApplied[active.Tenant] {
			continue
		}

		draft, err := store.GetDraft(ctx, active.CurrentDraftID)
		if err != nil {
			logger.Error("policy watcher: failed to read promoted draft; keeping current engine",
				"draft_id", active.CurrentDraftID, "tenant", active.Tenant, "err", err)
			continue
		}
		engine, err := policy.NewEngine(ctx, draft.RegoSource)
		if err != nil {
			logger.Error("policy watcher: failed to compile promoted draft; keeping current engine",
				"draft_id", active.CurrentDraftID, "tenant", active.Tenant, "err", err)
			continue
		}
		if _, err := reloader.SwapFor(active.Tenant, engine); err != nil {
			logger.Error("policy watcher: engine swap failed; keeping current engine",
				"draft_id", active.CurrentDraftID, "tenant", active.Tenant, "err", err)
			continue
		}
		lastApplied[active.Tenant] = active.CurrentDraftID
		logger.Info("policy watcher: swapped to promoted draft from sibling replica",
			"tenant", active.Tenant,
			"draft_id", active.CurrentDraftID,
			"promoted_at", active.PromotedAt,
			"promoted_by", active.PromotedBy,
		)
	}
	logger.Info("policy watcher stopped")
}

// loadRevocation constructs the revocation store. When postgresURL is
// set, a PostgresStore is returned (with the embedded migration
// applied). Otherwise an in-memory store is used.
//
// The Postgres store keeps its own connection pool and is intentionally
// not wired into a graceful-shutdown path here — the connection pool
// will close when the process exits, which is the right behavior for
// this lightweight service. A future operator-facing graceful-shutdown
// pass should call store.Close() to flush in-flight queries cleanly.
func loadRevocation(ctx context.Context, logger *slog.Logger, postgresURL string) (revocation.Store, string, error) {
	if postgresURL == "" {
		logger.Info("revocation store: in-memory (single-replica only, lost on restart)",
			"hint", "set INTENTGATE_POSTGRES_URL for durable, multi-replica-safe revocation")
		return revocation.NewMemoryStore(), "memory", nil
	}
	store, err := revocation.NewPostgresStore(ctx, postgresURL)
	if err != nil {
		return nil, "", err
	}
	logger.Info("revocation store: postgres", "dsn_set", true)
	return store, "postgres", nil
}

// loadKillSwitch constructs the kill-switch store. Postgres when a DSN
// is set (so an engaged breaker is honoured across every replica),
// otherwise in-memory (single-replica; engaged breakers are lost on
// restart, which is acceptable for dev and single-node installs).
func loadKillSwitch(ctx context.Context, logger *slog.Logger, postgresURL string) (killswitch.Store, string, error) {
	if postgresURL == "" {
		logger.Info("kill switch store: in-memory (single-replica only, lost on restart)",
			"hint", "set INTENTGATE_POSTGRES_URL for durable, multi-replica-safe kill switch")
		return killswitch.NewMemoryStore(), "memory", nil
	}
	store, err := killswitch.NewPostgresStore(ctx, postgresURL)
	if err != nil {
		return nil, "", err
	}
	logger.Info("kill switch store: postgres", "dsn_set", true)
	return store, "postgres", nil
}

// loadTaskBinder constructs the task-level intent binder (goal-drift).
// Disabled by default; set INTENTGATE_TASK_BINDING=true to enable. When
// enabled it uses Postgres if a DSN is set (so task drift state is shared
// across replicas) or an in-memory store otherwise. Thresholds default
// from task.DefaultConfig() and can be overridden via the
// INTENTGATE_TASK_* environment variables.
func loadTaskBinder(ctx context.Context, logger *slog.Logger, postgresURL string) (*task.Binder, task.Store, string, error) {
	v := os.Getenv("INTENTGATE_TASK_BINDING")
	if v != "true" && v != "1" {
		logger.Info("task binding: disabled",
			"hint", "set INTENTGATE_TASK_BINDING=true to enable goal-drift detection")
		return task.NewBinder(nil, task.Config{}), nil, "disabled", nil
	}

	cfg := task.DefaultConfig()
	cfg.Enabled = true
	if s := os.Getenv("INTENTGATE_TASK_MAX_CALLS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			cfg.MaxCalls = n
		}
	}
	if s := os.Getenv("INTENTGATE_TASK_WARN_SCORE"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			cfg.WarnScore = n
		}
	}
	if s := os.Getenv("INTENTGATE_TASK_BLOCK_SCORE"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			cfg.BlockScore = n
		}
	}

	if postgresURL == "" {
		logger.Info("task binding: enabled, in-memory store (single-replica only, lost on restart)")
		store := task.NewMemoryStore()
		return task.NewBinder(store, cfg), store, "memory", nil
	}
	store, err := task.NewPostgresStore(ctx, postgresURL)
	if err != nil {
		return nil, nil, "", err
	}
	logger.Info("task binding: enabled, postgres store", "dsn_set", true)
	return task.NewBinder(store, cfg), store, "postgres", nil
}
