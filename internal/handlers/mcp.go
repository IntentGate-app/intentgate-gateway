package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/actionguard"
	"github.com/IntentGate-app/intentgate-gateway/internal/approvals"
	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
	"github.com/IntentGate-app/intentgate-gateway/internal/budget"
	"github.com/IntentGate-app/intentgate-gateway/internal/capability"
	"github.com/IntentGate-app/intentgate-gateway/internal/credentials"
	"github.com/IntentGate-app/intentgate-gateway/internal/deception"
	"github.com/IntentGate-app/intentgate-gateway/internal/eastwest"
	"github.com/IntentGate-app/intentgate-gateway/internal/extractor"
	"github.com/IntentGate-app/intentgate-gateway/internal/faultisolation"
	"github.com/IntentGate-app/intentgate-gateway/internal/killswitch"
	"github.com/IntentGate-app/intentgate-gateway/internal/mcp"
	"github.com/IntentGate-app/intentgate-gateway/internal/metrics"
	"github.com/IntentGate-app/intentgate-gateway/internal/outputschema"
	"github.com/IntentGate-app/intentgate-gateway/internal/pii"
	"github.com/IntentGate-app/intentgate-gateway/internal/policy"
	"github.com/IntentGate-app/intentgate-gateway/internal/refverify"
	"github.com/IntentGate-app/intentgate-gateway/internal/revocation"
	"github.com/IntentGate-app/intentgate-gateway/internal/task"
	"github.com/IntentGate-app/intentgate-gateway/internal/tenantscope"
	"github.com/IntentGate-app/intentgate-gateway/internal/upstream"
	"github.com/IntentGate-app/intentgate-gateway/internal/zonescope"
)

// MCPHandlerConfig configures the /v1/mcp handler.
type MCPHandlerConfig struct {
	// Logger is required.
	Logger *slog.Logger
	// MasterKey is the HMAC key for capability tokens. May be nil only
	// when RequireCapability is false (dev mode).
	MasterKey []byte
	// RequireCapability rejects requests that don't carry a valid
	// capability token. When false (default in dev), missing tokens are
	// allowed through with a warning logged.
	RequireCapability bool
	// Extractor is the optional intent-extractor client. When nil, the
	// intent check is skipped. When non-nil, every tools/call carrying
	// an X-Intent-Prompt header is checked against the extracted intent.
	Extractor *extractor.Client
	// RequireIntent rejects requests that don't carry an
	// X-Intent-Prompt header. Independent of RequireCapability.
	RequireIntent bool
	// Policy evaluates the third of the four checks. Both a static
	// [*policy.Engine] (the original shape) and a [*policy.Reloader]
	// (live-swap on console-driven promote/rollback) satisfy the
	// interface; the handler doesn't care which one was wired. May be
	// nil only in dev mode (the policy check is skipped). main.go
	// always supplies one in normal operation.
	Policy policy.Evaluator
	// Budget is the per-token call counter store. When nil, the budget
	// check is skipped (and tokens with max_calls caveats produce a
	// startup-time error rather than a runtime one). When RequireBudget
	// is true, missing tokens at this stage are rejected.
	Budget budget.Store
	// RequireBudget rejects /v1/mcp tools/call requests that don't
	// have a verified capability token reaching the budget stage.
	// Default false (dev mode allows missing tokens).
	RequireBudget bool
	// Audit is the emitter for one-event-per-decision audit records.
	// When nil, a NullEmitter is substituted so the handler always has
	// a safe target.
	Audit audit.Emitter
	// Upstream forwards authorized tools/call requests to a downstream
	// MCP tool server. When nil, the handler returns a stub allow result
	// (useful for SDK tests, smoke targets, and any deployment that
	// hasn't wired a real upstream yet).
	Upstream *upstream.Client
	// Credentials brokers per-tool upstream secrets: the handler looks
	// up the credential for the tool being called and injects it on the
	// forwarded request, so agents never hold any tool secret. Tools
	// without a per-tool entry fall back to the global upstream
	// credential. nil disables per-tool brokering (global only).
	Credentials *credentials.Store
	// Revocation is the store the capability check consults to reject
	// tokens revoked after issuance. When nil, the revocation step is
	// skipped (useful for tests and minimal dev installs). Production
	// deployments always supply one (memory-backed for single-replica
	// dev, Postgres-backed for multi-replica or auditable installs).
	Revocation revocation.Store
	// KillSwitch is the incident-response circuit breaker, consulted in
	// the capability check before revocation. When an engaged entry
	// covers the request (a global kill, a kill on the token's tenant,
	// or a kill on the token's agent) the call is halted. A store error
	// fails closed. nil disables the check.
	KillSwitch killswitch.Store
	// TaskBinder is the task-level intent binder (goal-drift). When
	// enabled and the request carries an X-Task-Id header, it binds the
	// task to the plan the extractor declared at task start and scores
	// drift across the session, flagging or blocking on threshold. nil
	// or disabled makes the step a no-op.
	TaskBinder *task.Binder
	// Metrics is the Prometheus instrumentation. nil disables all
	// observation calls (the helpers nil-check internally so handlers
	// don't need to).
	Metrics *metrics.Metrics
	// Approvals is the queue the handler uses when policy returns
	// escalate. nil disables the escalation path: a policy
	// returning escalate without an approvals store wired
	// degrades to block ("escalate not configured").
	Approvals approvals.Store
	// ActionGuard is the effect-level guard (semantic Action IR resolver
	// plus mandatory hold and plan-level correlation). Runs just before
	// the Rego policy stage. nil disables the stage entirely, leaving the
	// four-check pipeline unchanged. See internal/actionguard.
	ActionGuard *actionguard.Guard
	// RefVerify is the reference-verification control: it verifies a
	// payment's payee against the system-of-record vendor master and
	// quarantines (holds for approval) on mismatch, unknown payee, or an
	// unavailable reference source (fail-closed). Runs right after the
	// action guard and before the segmentation/policy stages. nil disables
	// the stage entirely. See internal/refverify.
	RefVerify *refverify.Verifier
	// Deception is the inline decoy engagement detector. It runs at the
	// capability stage, before an out-of-scope honey-tool would be denied,
	// so a decoy touch is caught rather than lost. On a trip it contains
	// (kill switch + token revoke) and blocks. nil disables the stage. See
	// internal/deception.
	Deception *deception.Detector
	// DeceptionReporter mirrors a trip to the console Monitor
	// (best-effort). nil disables mirroring; trips are still recorded in
	// the gateway audit and SIEM regardless.
	DeceptionReporter deception.Reporter
	// EastWest authorizes agent-to-agent (east-west) calls in the
	// agent-as-tool model: a zone model with default-deny that keeps a
	// compromised agent from recruiting agents in other zones. Runs before
	// the policy stage. nil disables the check, and ordinary tool calls are
	// a no-op regardless. See internal/eastwest.
	EastWest *eastwest.Guard
	// ZoneScope enforces per-zone north-south scope on ordinary agent-to-tool
	// calls: which tools, and in which tenants, an agent in a given zone may
	// reach. Runs before the policy stage, after the east-west check, and only
	// on non-east-west calls. nil disables the check, and a zone with no
	// configured scope is a no-op. See internal/zonescope.
	ZoneScope *zonescope.Guard
	// ApprovalTimeout caps how long the handler waits for a human
	// decision before timing out and returning block. Zero falls
	// back to 5 minutes — operators with on-call humans can lower
	// this; deployments with offline reviewers should raise it.
	ApprovalTimeout time.Duration
	// ArgRedaction controls whether the gateway persists a redacted
	// view of tool-call argument values onto each audit event (see
	// [audit.RedactionMode]). Default RedactOff preserves the strict
	// keys-only privacy posture; RedactScalars opts into faithful
	// dry-run replay of numeric / boolean threshold rules without
	// ever logging free-form text. Read from
	// INTENTGATE_AUDIT_PERSIST_ARG_VALUES at startup.
	ArgRedaction audit.RedactionMode
	// ProvenanceEnabled turns on the opt-in AAI03 memory-provenance
	// check (pipeline check 3, between intent and policy). When
	// false (the default), the runProvenanceCheck stage is a no-op
	// and the gateway behaves exactly as the documented four-check
	// pipeline. When true, requests carrying an
	// X-Intent-Memory-Provenance header have their memory entries
	// verified against the session signing key derived from the
	// capability token's jti; failures return CodeProvenanceFailed
	// (-32014). Read from INTENTGATE_PROVENANCE_ENABLED at startup.
	// See internal/provenance and memos/aai03-memory-provenance-design.md.
	ProvenanceEnabled bool
	// PIIFilter is the opt-in LLM02 response-stream PII filter. When
	// non-nil, every successful upstream tool response has its text
	// content scanned for PII matching the tenant's configured pattern
	// set; matches are either redacted in-place (default) or block the
	// response entirely (-32015). When nil (the default), the filter
	// stage is a no-op. See internal/pii and
	// memos/llm02-pii-filter-design.md.
	PIIFilter *pii.Filter
	// OutputSchemas is the opt-in LLM05 response-schema registry. When
	// non-nil and a schema is declared for the requested tool, every
	// successful upstream response is validated against its declared
	// shape. Violations are either stripped in-place (default) or
	// block the response entirely (-32016). When nil (the default),
	// the stage is a no-op. See internal/outputschema and
	// memos/llm05-output-schema-design.md.
	OutputSchemas *outputschema.Registry
	// TenantScope is the opt-in LLM08 per-tenant vector-scope
	// enforcer. When non-nil and the requested tool is marked
	// scoped, the gateway verifies the tool-call's tenant filter
	// argument matches the verified capability token's tenant claim
	// before forwarding. Cross-tenant queries return -32017. When
	// nil (the default), the stage is a no-op. See
	// internal/tenantscope and memos/llm08-tenant-scope-design.md.
	TenantScope *tenantscope.Enforcer
	// FaultIsolation is the opt-in AGENT08 per-tool circuit-breaker
	// + bulkhead. When non-nil, every upstream forward goes through
	// an Acquire / release gate keyed on tool name; a slow or
	// failing tool fails-fast for that tool only without cascading
	// into the rest of the agent's traffic. When nil (the default),
	// the stage is a no-op. See internal/faultisolation and
	// memos/agent08-fault-isolation-design.md.
	FaultIsolation *faultisolation.Isolator
}

type mcpHandler struct {
	cfg MCPHandlerConfig
}

// NewMCPHandler returns the HTTP handler for POST /v1/mcp.
//
// Pipeline:
//
//  1. Parse the JSON-RPC envelope.
//  2. Dispatch on method. Only "tools/call" is implemented.
//  3. Capability check: verify the Bearer token's HMAC chain and
//     evaluate its caveats against the requested tool. Returns
//     CodeCapabilityFailed (-32010) on failure.
//  4. Intent check: if an X-Intent-Prompt header is present and an
//     extractor is configured, the gateway extracts structured intent
//     (cached) and verifies the requested tool is permitted by it.
//     Returns CodeIntentFailed (-32011) on failure.
//  5. Provenance check (OPT-IN): when ProvenanceEnabled is true and
//     the request carries an X-Intent-Memory-Provenance header, the
//     gateway re-derives the session signing key from the capability
//     token's jti, verifies the HMAC over each declared memory entry,
//     and walks the per-session prev_hash chain. Returns
//     CodeProvenanceFailed (-32014) on failure. Closes the
//     sophisticated AAI03 (Memory Poisoning) case. See
//     memos/aai03-memory-provenance-design.md.
//  6. Policy check: evaluate the request against the configured Rego
//     policy bundle. Returns CodePolicyFailed (-32012) on deny.
//  7. Budget check: increment the per-token counter, deny when any
//     max_calls caveat in the verified token is exceeded. Returns
//     CodeBudgetFailed (-32013) on deny.
//  8. Return the stub allow response.
func NewMCPHandler(cfg MCPHandlerConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Audit == nil {
		cfg.Audit = audit.NewNullEmitter()
	}
	return &mcpHandler{cfg: cfg}
}

func (h *mcpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	const maxBody = 1 << 20
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		h.write(w, mcp.NewErrorResponse(nil, mcp.CodeParseError,
			"failed to read request body", err.Error()))
		return
	}

	var req mcp.Request
	if err := json.Unmarshal(body, &req); err != nil {
		h.write(w, mcp.NewErrorResponse(nil, mcp.CodeParseError,
			"invalid JSON", err.Error()))
		return
	}
	if err := req.Validate(); err != nil {
		h.write(w, mcp.NewErrorResponse(req.ID, mcp.CodeInvalidRequest,
			err.Error(), nil))
		return
	}

	notification := req.IsNotification()

	switch req.Method {
	case mcp.MethodToolsCall:
		resp := h.handleToolsCall(r.Context(), &req, r)
		if notification {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.write(w, resp)

	case mcp.MethodToolsList, mcp.MethodInitialize, mcp.MethodPing:
		// Discovery + lifecycle methods: pure passthrough to the upstream
		// when configured, minimal local fallback otherwise. No
		// four-check pipeline (no tool name to authorize) and no audit
		// event (audit is for authorization decisions, not handshake).
		resp := h.handlePassthrough(r.Context(), &req, body)
		if notification {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.write(w, resp)

	default:
		h.cfg.Logger.Info("mcp method not implemented",
			"method", req.Method,
			"notification", notification,
		)
		if notification {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.write(w, mcp.NewErrorResponse(req.ID, mcp.CodeMethodNotFound,
			"method not implemented in v0.1: "+req.Method, nil))
	}
}

// handleToolsCall runs each enabled check in order then returns the
// stub allow result. Every decision (allow or block at any stage)
// emits one audit event before the response is returned.
func (h *mcpHandler) handleToolsCall(ctx context.Context, req *mcp.Request, r *http.Request) *mcp.Response {
	start := time.Now()

	params, err := mcp.ParseToolCallParams(req.Params)
	if err != nil {
		return mcp.NewErrorResponse(req.ID, mcp.CodeInvalidParams,
			"invalid tools/call params", err.Error())
	}
	if params.Name == "" {
		return mcp.NewErrorResponse(req.ID, mcp.CodeInvalidParams,
			"params.name is required", nil)
	}

	var (
		capResult capabilityCheckResult
		intResult intentCheckResult
	)

	// Check 1: capability.
	capStart := time.Now()
	capResult = h.runCapabilityCheck(r, params.Name)
	h.cfg.Metrics.ObserveCheck("capability", checkDecision(capResult.err, capResult.summary), time.Since(capStart))

	// Deception: catch a decoy touch inline. This runs before the
	// capability error is acted on, because a honey-tool is in no token's
	// scope: if the capability check rejected it as out-of-scope first, the
	// compromise signal would be lost. A trip fires the kill switch for the
	// agent and revokes its token in the same second, then blocks.
	if h.cfg.Deception != nil {
		dStart := time.Now()
		var tokenID, tokenTenant string
		if capResult.token != nil {
			tokenID = capResult.token.ID
			tokenTenant = capResult.token.Tenant
		}
		dRes := h.cfg.Deception.Check(deception.Input{Tool: params.Name, TokenID: tokenID})
		dVerdict := "pass"
		if dRes.Tripped {
			dVerdict = "tripped"
		}
		h.cfg.Metrics.ObserveCheck("deception", dVerdict, time.Since(dStart))
		if dRes.Tripped {
			if dRes.Contain {
				if capResult.agentID != "" && h.cfg.KillSwitch != nil {
					_ = h.cfg.KillSwitch.Engage(ctx, killswitch.Entry{
						Type:   killswitch.ScopeAgent,
						Tenant: tokenTenant,
						Value:  capResult.agentID,
						Reason: dRes.Reason,
						SetAt:  time.Now().UTC(),
					})
				}
				if tokenID != "" && h.cfg.Revocation != nil {
					_ = h.cfg.Revocation.Revoke(ctx, tokenID, dRes.Reason, tokenTenant)
				}
			}
			if h.cfg.DeceptionReporter != nil {
				agent := capResult.agentID
				if agent == "" {
					agent = "unattributed agent"
				}
				go h.cfg.DeceptionReporter.Report(context.Background(), deception.Trip{
					DecoyID:     dRes.Decoy.ID,
					DecoyName:   dRes.Decoy.Name,
					Pillar:      dRes.Decoy.Pillar,
					Agent:       agent,
					Severity:    string(dRes.Severity),
					ActionTaken: string(dRes.Action),
					Detail:      dRes.Reason,
				})
			}
			h.cfg.Logger.Info("mcp tools/call blocked",
				"tool", params.Name, "check", "deception", "agent", capResult.agentID,
				"decoy", dRes.Decoy.Name, "action", string(dRes.Action), "reason", dRes.Reason)
			h.emitAudit(ctx, r, params, capResult, intResult,
				audit.DecisionBlock, audit.CheckDeception, dRes.Reason, start, 0)
			return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
				"deception: decoy touched", dRes.Reason)
		}
	}

	if capResult.err != nil {
		h.cfg.Logger.Info("mcp tools/call blocked",
			"tool", params.Name, "check", "capability",
			"reason", capResult.err.Error())
		h.emitAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, audit.CheckCapability, capResult.err.Error(), start, 0)
		return mcp.NewErrorResponse(req.ID, mcp.CodeCapabilityFailed,
			"capability check failed", capResult.err.Error())
	}

	// Check 2: intent.
	intStart := time.Now()
	intResult = h.runIntentCheck(ctx, r, params.Name, capResult.agentID)
	h.cfg.Metrics.ObserveCheck("intent", checkDecision(intResult.err, intResult.summary), time.Since(intStart))
	if intResult.err != nil {
		h.cfg.Logger.Info("mcp tools/call blocked",
			"tool", params.Name, "check", "intent",
			"agent", capResult.agentID, "reason", intResult.err.Error())
		h.emitAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, audit.CheckIntent, intResult.err.Error(), start, 0)
		return mcp.NewErrorResponse(req.ID, mcp.CodeIntentFailed,
			"intent check failed", intResult.err.Error())
	}

	// Check 2b (OPT-IN): task-level intent binding (goal-drift). Binds
	// the whole task (identified by the X-Task-Id header) to the plan the
	// extractor declared at task start, and scores drift across the
	// session: off-plan tool calls, distinct-tool growth, and running
	// past the call budget. Flags on the warn threshold (allow + audit)
	// and blocks on the block threshold. No-op when disabled or when the
	// request carries no task id. A store error is advisory (log + allow),
	// since binding measures drift rather than gating a single action.
	if h.cfg.TaskBinder != nil && h.cfg.TaskBinder.Enabled() {
		if taskID := r.Header.Get("X-Task-Id"); taskID != "" {
			var plan []string
			var summary string
			if intResult.intent != nil {
				plan = intResult.intent.AllowedTools
				summary = intResult.intent.Summary
			}
			var taskTenant string
			if capResult.token != nil {
				taskTenant = capResult.token.Tenant
			}
			bindRes, berr := h.cfg.TaskBinder.Bind(
				ctx, taskTenant, capResult.agentID, taskID, params.Name, plan, summary)
			if berr != nil {
				h.cfg.Logger.Error("task binding store error; allowing (advisory)",
					"task", taskID, "err", berr)
			}
			switch bindRes.Outcome {
			case task.OutcomeBlock:
				h.cfg.Logger.Info("mcp tools/call blocked",
					"tool", params.Name, "check", "task", "agent", capResult.agentID,
					"task", taskID, "drift", bindRes.Drift, "reason", bindRes.Reason)
				h.emitAudit(ctx, r, params, capResult, intResult,
					audit.DecisionBlock, audit.CheckIntent,
					fmt.Sprintf("task drift halted (drift=%d): %s", bindRes.Drift, bindRes.Reason),
					start, 0)
				return mcp.NewErrorResponse(req.ID, mcp.CodeIntentFailed,
					"task drift: session halted", bindRes.Reason)
			case task.OutcomeFlag:
				h.emitAudit(ctx, r, params, capResult, intResult,
					audit.DecisionAllow, audit.CheckIntent,
					fmt.Sprintf("task drift flagged (drift=%d): %s", bindRes.Drift, bindRes.Reason),
					start, 0)
			}
		}
	}

	// Check 3 (OPT-IN): provenance. Only fires when the operator has
	// turned on the AAI03 memory-provenance feature for this gateway.
	// When disabled, the stage is a no-op and the pipeline behaves
	// exactly as the four-check pipeline always has. When enabled,
	// rejects requests whose declared memory entries fail HMAC or
	// chain verification (CodeProvenanceFailed = -32014).
	var capJTI string
	if capResult.token != nil {
		capJTI = capResult.token.ID
	}
	provStart := time.Now()
	provResult := h.runProvenanceCheck(ctx, r.Header.Get(HeaderIntentMemoryProvenance), capJTI)
	h.cfg.Metrics.ObserveCheck("provenance", checkDecision(provResult.err, provResult.summary), time.Since(provStart))
	if provResult.err != nil {
		h.cfg.Logger.Info("mcp tools/call blocked",
			"tool", params.Name, "check", "provenance",
			"agent", capResult.agentID,
			"err_kind", provResult.errKind,
			"reason", provResult.err.Error())
		h.emitAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, audit.CheckProvenance, provResult.err.Error(), start, 0)
		return mcp.NewErrorResponse(req.ID, mcp.CodeProvenanceFailed,
			"provenance check failed", provResult.err.Error())
	}

	// Check 3c (OPT-IN): action effect guard. Resolves the tool call to its
	// canonical effect (Action IR) and applies deterministic controls a
	// per-call string policy cannot express: a mandatory hold on irreversible
	// high-value or unbounded-destructive actions, and plan-level correlation
	// across the session (for example a payment to a party the same agent
	// created earlier in this task chain, the invoice-fraud pattern). No-op
	// when ActionGuard is nil. The session key is the task id (same identifier
	// the goal-drift binder uses); when absent we fall back to the agent id so
	// correlation still works within an agent's activity.
	if h.cfg.ActionGuard != nil {
		agStart := time.Now()
		agSession := r.Header.Get("X-Task-Id")
		if agSession == "" {
			agSession = capResult.agentID
		}
		agRes := h.cfg.ActionGuard.Check(agSession, params.Name, params.Arguments)
		h.cfg.Metrics.ObserveCheck("action", string(agRes.Verdict), time.Since(agStart))
		switch agRes.Verdict {
		case actionguard.VerdictBlock:
			h.cfg.Logger.Info("mcp tools/call blocked",
				"tool", params.Name, "check", "action", "agent", capResult.agentID,
				"rule", agRes.Rule, "reason", agRes.Reason)
			h.emitAudit(ctx, r, params, capResult, intResult,
				audit.DecisionBlock, audit.CheckActionGuard,
				fmt.Sprintf("action guard blocked (%s): %s", agRes.Rule, agRes.Reason), start, 0)
			return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
				"action guard blocked", agRes.Reason)
		case actionguard.VerdictEscalate:
			if escResp := h.runApprovalFlow(ctx, r, req, params, capResult, intResult, audit.CheckPolicy, agRes.Reason, false, start); escResp != nil {
				return escResp
			}
		}
	}

	// Check 3c-bis (OPT-IN): reference verification. Before a payment leaves
	// the gateway, verify the payee/destination against the system-of-record
	// vendor master. A match falls through; a mismatch, an unknown payee, or an
	// unavailable reference source quarantines the call (holds for human
	// approval) — never pay a payee we cannot verify. No-op when RefVerify is
	// nil. Verification is stateless: it depends only on the call and the master.
	if h.cfg.RefVerify != nil {
		rvStart := time.Now()
		rvRes := h.cfg.RefVerify.Check(params.Name, params.Arguments)
		h.cfg.Metrics.ObserveCheck("refverify", string(rvRes.Verdict), time.Since(rvStart))
		switch rvRes.Verdict {
		case refverify.VerdictBlock:
			h.cfg.Logger.Info("mcp tools/call blocked",
				"tool", params.Name, "check", "refverify", "agent", capResult.agentID,
				"rule", rvRes.Rule, "reason", rvRes.Reason)
			h.emitAudit(ctx, r, params, capResult, intResult,
				audit.DecisionBlock, audit.CheckRefVerify,
				fmt.Sprintf("reference verification blocked (%s): %s", rvRes.Rule, rvRes.Reason), start, 0)
			return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
				"reference verification failed", rvRes.Reason)
		case refverify.VerdictQuarantine:
			if escResp := h.runApprovalFlow(ctx, r, req, params, capResult, intResult, audit.CheckRefVerify, rvRes.Reason, false, start); escResp != nil {
				return escResp
			}
		}
	}

	// Caller zone and tenant for the segmentation checks. Both come from the
	// signed capability token when present, so they are authoritative and
	// cannot be forged. The east-west guard falls back to its config
	// directory when the token carries no zone.
	var callerZone, callerTenant string
	if capResult.token != nil {
		callerZone = capResult.token.Zone
		callerTenant = capResult.token.Tenant
	}

	// Check 3d: east-west authorization (agent-to-agent). In the agent-as-tool
	// model, a call to a tool named like an agent target is one agent calling
	// another; the guard applies a zone model with default-deny so a
	// compromised agent cannot recruit agents in other zones. No-op when
	// EastWest is nil or the call is not an agent-to-agent call.
	eastWestCall := false
	if h.cfg.EastWest != nil {
		ewStart := time.Now()
		ewRes := h.cfg.EastWest.Check(capResult.agentID, callerZone, params.Name)
		eastWestCall = ewRes.EastWest
		if ewRes.EastWest {
			h.cfg.Metrics.ObserveCheck("eastwest", string(ewRes.Verdict), time.Since(ewStart))
			if ewRes.Verdict == eastwest.VerdictDeny {
				h.cfg.Logger.Info("mcp tools/call blocked",
					"tool", params.Name, "check", "eastwest", "agent", capResult.agentID,
					"callee", ewRes.CalleeAgent, "caller_zone", ewRes.CallerZone,
					"callee_zone", ewRes.CalleeZone, "reason", ewRes.Reason)
				h.emitAudit(ctx, r, params, capResult, intResult,
					audit.DecisionBlock, audit.CheckEastWest,
					fmt.Sprintf("east-west denied: %s", ewRes.Reason), start, 0)
				return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
					"east-west denied", ewRes.Reason)
			}
			// Second east-west gate: the caller token's own agent-to-agent
			// allowlist (CaveatCalleeAllow). The zone policy above and this
			// per-token allowlist are independent; both must permit the call.
			// A token with no callee_allow caveat is unrestricted here.
			if capResult.token != nil {
				if ok, reason := capResult.token.CanCall(ewRes.CalleeAgent, ewRes.CalleeZone); !ok {
					h.cfg.Logger.Info("mcp tools/call blocked",
						"tool", params.Name, "check", "eastwest_token", "agent", capResult.agentID,
						"callee", ewRes.CalleeAgent, "callee_zone", ewRes.CalleeZone, "reason", reason)
					h.emitAudit(ctx, r, params, capResult, intResult,
						audit.DecisionBlock, audit.CheckEastWest,
						fmt.Sprintf("east-west denied by token: %s", reason), start, 0)
					return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
						"east-west denied", reason)
				}
			}
		}
	}

	// Check 3e: per-zone north-south scope (agent-to-tool). The caller zone's
	// allowlist governs which tools, and in which tenants, it may reach.
	// Skipped for east-west calls, which the east-west guard already governs.
	// No-op when ZoneScope is nil or the caller's zone has no configured scope.
	if h.cfg.ZoneScope != nil && !eastWestCall {
		zsStart := time.Now()
		zsRes := h.cfg.ZoneScope.Check(callerZone, callerTenant, params.Name)
		if zsRes.Enforced {
			h.cfg.Metrics.ObserveCheck("zonescope", string(zsRes.Verdict), time.Since(zsStart))
			if zsRes.Verdict == zonescope.VerdictDeny {
				h.cfg.Logger.Info("mcp tools/call blocked",
					"tool", params.Name, "check", "zonescope", "agent", capResult.agentID,
					"zone", callerZone, "tenant", callerTenant, "reason", zsRes.Reason)
				h.emitAudit(ctx, r, params, capResult, intResult,
					audit.DecisionBlock, audit.CheckZoneScope,
					fmt.Sprintf("zone scope denied: %s", zsRes.Reason), start, 0)
				return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
					"zone scope denied", zsRes.Reason)
			}
		}
	}

	// Check 4: policy (OPA / Rego).
	polStart := time.Now()
	polResult := h.runPolicyCheck(ctx, params, capResult, intResult)
	h.cfg.Metrics.ObserveCheck("policy", checkDecision(polResult.err, polResult.summary), time.Since(polStart))
	if polResult.err != nil {
		h.cfg.Logger.Info("mcp tools/call blocked",
			"tool", params.Name, "check", "policy",
			"agent", capResult.agentID, "reason", polResult.err.Error())
		h.emitAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, audit.CheckPolicy, polResult.err.Error(), start, 0,
			withRequiresStepUp(polResult.requiresStepUp))
		return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
			"policy check failed", polResult.err.Error())
	}

	// Check 3b: human approval. Triggered when the Rego policy
	// returns {"escalate": true}. The handler pauses the request
	// here and resumes when an operator decides via
	// /v1/admin/approvals/{id}/decide. Failure modes (queue not
	// wired, queue error, timeout, rejection) all collapse to a
	// CodePolicyFailed block — the agent doesn't need to know the
	// flow took a detour through human review.
	if polResult.escalate {
		if escResp := h.runApprovalFlow(ctx, r, req, params, capResult, intResult, audit.CheckPolicy, polResult.reason, polResult.requiresStepUp, start); escResp != nil {
			return escResp
		}
	}

	// Check 4: budget.
	bdgStart := time.Now()
	bdgResult := h.runBudgetCheck(ctx, capResult)
	h.cfg.Metrics.ObserveCheck("budget", checkDecision(bdgResult.err, bdgResult.summary), time.Since(bdgStart))
	if bdgResult.err != nil {
		h.cfg.Logger.Info("mcp tools/call blocked",
			"tool", params.Name, "check", "budget",
			"agent", capResult.agentID, "reason", bdgResult.err.Error())
		h.emitAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, audit.CheckBudget, bdgResult.err.Error(), start, 0)
		return mcp.NewErrorResponse(req.ID, mcp.CodeBudgetFailed,
			"budget check failed", bdgResult.err.Error())
	}

	// Request-side PII filter (LLM02 bidirectional close).
	//
	// Same engine as the response-side filter; scans every string value
	// in params.Arguments (recursively into nested objects/arrays). On
	// Redact, argument values are rewritten in place — the agent doesn't
	// get to recover the original. On Block/Escalate, the call is
	// refused and the matched values never leave the gateway.
	//
	// Audit row carries direction="request" so the chain distinguishes
	// inbound from outbound matches. Counts only, never values — same
	// principle the response side already follows.
	reqFilter := h.requestPIIFilter(polResult.piiOverride, capResult.agentID, params.Name)
	if reqFilter != nil && len(params.Arguments) > 0 {
		piiDec := reqFilter.ApplyToMCPRequest(params.Arguments)
		switch piiDec.Action {
		case pii.ActionBlock, pii.ActionEscalate:
			h.cfg.Metrics.ObserveCheck("pii_request", "block", time.Since(start))
			h.emitAudit(ctx, r, params, capResult, intResult,
				audit.DecisionBlock, audit.CheckPII,
				fmt.Sprintf("pii filter blocked request (classes=%v)", piiDec.MatchedClasses),
				start, 0,
				withRequiresStepUp(polResult.requiresStepUp))
			return mcp.NewErrorResponse(req.ID, mcp.CodePIIBlocked,
				"request blocked by pii filter",
				map[string]any{
					"counts":    piiDec.Counts,
					"classes":   piiDec.MatchedClasses,
					"direction": "request",
				})
		case pii.ActionRedact:
			// Arguments mutated in place by ApplyToMCPRequest. Log and
			// continue to forward. The audit row records what the filter
			// did so an operator can reconstruct downstream behaviour.
			h.cfg.Metrics.ObserveCheck("pii_request", "redact", time.Since(start))
			h.emitAudit(ctx, r, params, capResult, intResult,
				audit.DecisionAllow, audit.CheckPII,
				fmt.Sprintf("pii filter redacted request (classes=%v)", piiDec.MatchedClasses),
				start, 0,
				withRequiresStepUp(polResult.requiresStepUp))
		case pii.ActionAllow:
			h.cfg.Metrics.ObserveCheck("pii_request", "allow", time.Since(start))
			// No audit row on Allow with zero matches — same noise
			// discipline as the response-side filter.
		}
	}

	// LLM08 tenant scope check (request-side). Runs after the request
	// PII filter so injected values are scanned for PII first. For
	// tools the operator has declared tenant-scoped, the gateway
	// verifies the tool-call's tenant filter argument matches the
	// verified capability token's tenant claim. Mismatched, missing
	// (when not auto-injectable), or wildcarded filters return
	// CodeTenantScopeViolation (-32017). Closes the cross-tenant
	// query path on shared vector / RAG backends.
	if h.cfg.TenantScope != nil && h.cfg.TenantScope.IsScoped(params.Name) {
		var tokenTenant string
		if capResult.token != nil {
			tokenTenant = capResult.token.Tenant
		}
		tsDec := h.cfg.TenantScope.Check(params.Name, tokenTenant, params.Arguments)
		if tsDec.Violation != "" && !tsDec.Allowed() {
			h.cfg.Metrics.ObserveCheck("tenant_scope", "block", time.Since(start))
			h.emitAudit(ctx, r, params, capResult, intResult,
				audit.DecisionBlock, audit.CheckTenantScope,
				fmt.Sprintf("tenant scope %s on tool %q", tsDec.Violation, params.Name),
				start, 0,
				withRequiresStepUp(polResult.requiresStepUp))
			return mcp.NewErrorResponse(req.ID, mcp.CodeTenantScopeViolation,
				"tenant scope violation",
				map[string]any{
					"violation": string(tsDec.Violation),
					"tool":      params.Name,
				})
		}
		if tsDec.Mutated {
			h.cfg.Metrics.ObserveCheck("tenant_scope", "redact", time.Since(start))
			h.emitAudit(ctx, r, params, capResult, intResult,
				audit.DecisionAllow, audit.CheckTenantScope,
				fmt.Sprintf("tenant scope injected on tool %q", params.Name),
				start, 0,
				withRequiresStepUp(polResult.requiresStepUp))
		} else if tsDec.Violation == "" {
			h.cfg.Metrics.ObserveCheck("tenant_scope", "allow", time.Since(start))
		}
	}

	// Argument values may contain sensitive data — log only the keys.
	argKeys := make([]string, 0, len(params.Arguments))
	for k := range params.Arguments {
		argKeys = append(argKeys, k)
	}
	h.cfg.Logger.Info("mcp tools/call authorized",
		"tool", params.Name,
		"agent", capResult.agentID,
		"capability", capResult.summary,
		"intent", intResult.summary,
		"policy", polResult.summary,
		"budget", bdgResult.summary,
		"arg_keys", argKeys,
	)

	// All four checks passed. Either forward to the configured upstream
	// or return the stub allow.
	if h.cfg.Upstream != nil {
		return h.forwardToUpstream(ctx, r, req, params, capResult, intResult, polResult.requiresStepUp, polResult.piiOverride, start)
	}

	h.emitAudit(ctx, r, params, capResult, intResult,
		audit.DecisionAllow, audit.CheckNone, "all four checks passed (stub upstream)", start, 0,
		withRequiresStepUp(polResult.requiresStepUp))

	result := mcp.ToolCallResult{
		Content: []mcp.ContentBlock{{
			Type: "text",
			Text: "stub: no upstream configured; gateway authorized this call",
		}},
		IsError: false,
		IntentGate: &mcp.IntentGateMetadata{
			Decision:  "allow",
			Reason:    "stub: no upstream configured",
			LatencyMS: time.Since(start).Milliseconds(),
		},
	}
	resp, err := mcp.NewResultResponse(req.ID, result)
	if err != nil {
		return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
			"failed to encode result", err.Error())
	}
	return resp
}

// forwardToUpstream re-serializes the validated request, sends it to
// the configured upstream MCP server, and translates the upstream
// response (or failure) back to the caller.
//
// Successful forwards inject the gateway's _intentgate metadata into
// the upstream's result object. Operational failures (timeout,
// transport, non-2xx) collapse into a JSON-RPC error with the
// gateway's CodeInternalError plus a structured data field, AND emit
// an audit event with check=upstream so SOC analysts can distinguish
// "blocked by gateway" from "couldn't reach upstream".
//
// Upstream-side JSON-RPC errors (a 200 OK carrying an error object —
// e.g. tool says "db unavailable") are NOT operational failures here:
// the upstream answered, the answer just says no. The body is
// returned to the caller unchanged.
func (h *mcpHandler) forwardToUpstream(
	ctx context.Context,
	r *http.Request,
	req *mcp.Request,
	params *mcp.ToolCallParams,
	cap capabilityCheckResult,
	intent intentCheckResult,
	requiresStepUp bool,
	piiOverride *policy.PIIFilterSpec,
	start time.Time,
) *mcp.Response {
	// Re-serialize the validated request so we forward exactly the
	// envelope the gateway accepted (preserves id and params).
	body, err := json.Marshal(req)
	if err != nil {
		h.emitAudit(ctx, r, params, cap, intent,
			audit.DecisionBlock, audit.CheckUpstream,
			"failed to re-serialize request: "+err.Error(), start, 0,
			withRequiresStepUp(requiresStepUp))
		return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
			"failed to encode upstream request", err.Error())
	}

	// AGENT08 fault-isolation gate. Acquire a per-tool permit before
	// the forward. Open circuit / full bulkhead returns fail-fast
	// CodeUpstreamUnavailable (-32018) without ever calling the
	// upstream. When the isolator is nil, release is a no-op closure
	// and the call proceeds unchanged.
	var release func(faultisolation.Outcome)
	if h.cfg.FaultIsolation != nil {
		var fiErr error
		release, fiErr = h.cfg.FaultIsolation.Acquire(ctx, params.Name)
		if fiErr != nil {
			reason := "circuit_open"
			if errors.Is(fiErr, faultisolation.ErrBulkheadFull) {
				reason = "bulkhead_full"
			}
			h.cfg.Logger.Warn("upstream forward refused (fault isolation)",
				"tool", params.Name,
				"agent", cap.agentID,
				"reason", reason,
			)
			h.cfg.Metrics.ObserveCheck("fault_isolation", "block", time.Since(start))
			h.emitAudit(ctx, r, params, cap, intent,
				audit.DecisionBlock, audit.CheckFaultIsolation,
				"upstream forward refused: "+reason, start, 0,
				withRequiresStepUp(requiresStepUp))
			return mcp.NewErrorResponse(req.ID, mcp.CodeUpstreamUnavailable,
				"upstream temporarily unavailable",
				map[string]any{
					"reason": reason,
					"tool":   params.Name,
				})
		}
	}
	upStart := time.Now()
	// Per-tool credential brokering: inject this tool's upstream secret
	// (falls back to the global credential when no per-tool entry).
	upResp, err := h.cfg.Upstream.Forward(ctx, body, h.cfg.Credentials.HeaderFor(params.Name))
	upDur := time.Since(upStart)
	// Record outcome on the breaker/bulkhead. Status < 500 and no
	// transport error counts as a success; everything else as a
	// failure. The breaker doesn't care about JSON-RPC application
	// errors (e.g. tool says "db unavailable" with a 200 body) —
	// those are the upstream's correct behaviour and the gateway
	// has no business opening its breaker for them.
	if release != nil {
		switch {
		case err != nil:
			release(faultisolation.OutcomeFailure)
		case upResp != nil && upResp.Status >= 500:
			release(faultisolation.OutcomeFailure)
		default:
			release(faultisolation.OutcomeSuccess)
		}
	}
	if err != nil {
		var uerr *upstream.Error
		if errors.As(err, &uerr) {
			reason := uerr.Error()
			h.cfg.Logger.Warn("upstream forward failed",
				"tool", params.Name,
				"agent", cap.agentID,
				"kind", uerr.Kind.String(),
				"status", uerr.Status,
				"reason", reason,
			)
			h.cfg.Metrics.ObserveUpstream(uerr.Kind.String(), upDur)
			h.cfg.Metrics.ObserveCheck("upstream", "block", upDur)
			h.emitAudit(ctx, r, params, cap, intent,
				audit.DecisionBlock, audit.CheckUpstream, reason, start, uerr.Status,
				withRequiresStepUp(requiresStepUp))
			return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
				"upstream "+uerr.Kind.String(),
				map[string]any{
					"upstream_status": uerr.Status,
					"detail":          reason,
				})
		}
		// Defensive: any non-typed error from Forward is treated as transport.
		h.cfg.Metrics.ObserveUpstream("transport", upDur)
		h.cfg.Metrics.ObserveCheck("upstream", "block", upDur)
		h.emitAudit(ctx, r, params, cap, intent,
			audit.DecisionBlock, audit.CheckUpstream, err.Error(), start, 0,
			withRequiresStepUp(requiresStepUp))
		return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
			"upstream error", err.Error())
	}
	h.cfg.Metrics.ObserveUpstream("success", upDur)
	h.cfg.Metrics.ObserveCheck("upstream", "allow", upDur)

	// Successful forward. Inject _intentgate metadata into the result
	// object so the caller can see the gateway's decision summary
	// alongside the tool's response.
	var parsed mcp.Response
	if err := json.Unmarshal(upResp.Body, &parsed); err != nil {
		h.cfg.Logger.Error("upstream returned non-JSON-RPC body",
			"tool", params.Name,
			"err", err,
		)
		h.emitAudit(ctx, r, params, cap, intent,
			audit.DecisionBlock, audit.CheckUpstream,
			"upstream returned non-JSON-RPC body: "+err.Error(), start, upResp.Status,
			withRequiresStepUp(requiresStepUp))
		return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
			"upstream returned non-JSON-RPC body", err.Error())
	}

	// LLM02 PII filter — opt-in. Runs after the upstream returns its
	// response, before we inject _intentgate metadata or audit the
	// allow. Two configuration paths, tried in priority order:
	//
	//  1. Per-request Rego override (piiOverride) — built from the
	//     policy decision's `pii_filter` field. Used when the policy
	//     author wants endpoint- or tool-specific PII config (e.g.
	//     allowing PII through for an account-holder reading their
	//     own data).
	//  2. Static gateway filter (h.cfg.PIIFilter) — set at startup
	//     from env vars / config file. The default when no override.
	//
	// The filter may redact text content blocks in-place (safe to
	// forward) or block the response entirely (-32015 to the agent).
	// When neither config path produces a filter, this is a no-op.
	activeFilter := h.cfg.PIIFilter
	if piiOverride != nil {
		// Build a one-shot filter from the policy spec. Errors
		// (invalid regex, ReDoS) fail closed: the original static
		// filter (if any) still applies; we don't silently bypass.
		if f, err := pii.NewFilterFromSpec(pii.FilterSpec{
			Enabled:          piiOverride.Enabled,
			Patterns:         piiOverride.Patterns,
			DefaultAction:    piiOverride.DefaultAction,
			PerPatternAction: piiOverride.PerPatternAction,
			CustomPatterns:   piiOverrideToCustomPatterns(piiOverride.CustomPatterns),
		}); err == nil {
			activeFilter = f
		} else {
			h.cfg.Logger.Warn("pii filter override invalid; using static config",
				"agent", cap.agentID, "tool", params.Name, "err", err)
		}
	}
	if activeFilter != nil && parsed.Result != nil {
		redactedResult, piiDec := activeFilter.ApplyToMCPResult(parsed.Result)
		switch piiDec.Action {
		case pii.ActionBlock, pii.ActionEscalate:
			// Refuse the response. The matched values are NOT returned
			// or persisted — only per-class counts go into the audit row.
			h.cfg.Metrics.ObserveCheck("pii", "block", time.Since(start))
			h.emitAudit(ctx, r, params, cap, intent,
				audit.DecisionBlock, audit.CheckPII,
				fmt.Sprintf("pii filter blocked response (classes=%v)", piiDec.MatchedClasses),
				start, upResp.Status,
				withRequiresStepUp(requiresStepUp))
			return mcp.NewErrorResponse(req.ID, mcp.CodePIIBlocked,
				"response blocked by pii filter",
				map[string]any{
					"counts":  piiDec.Counts,
					"classes": piiDec.MatchedClasses,
				})
		case pii.ActionRedact:
			parsed.Result = redactedResult
			h.cfg.Metrics.ObserveCheck("pii", "redact", time.Since(start))
			h.emitAudit(ctx, r, params, cap, intent,
				audit.DecisionAllow, audit.CheckPII,
				fmt.Sprintf("pii filter redacted response (classes=%v)", piiDec.MatchedClasses),
				start, upResp.Status,
				withRequiresStepUp(requiresStepUp))
			// fall through to inject metadata + return the (redacted) response
		case pii.ActionAllow:
			h.cfg.Metrics.ObserveCheck("pii", "allow", time.Since(start))
			// No audit row when nothing matched — same noise-discipline
			// as the provenance check (which is also opt-in and
			// silent when it has nothing to say).
		}
	}

	// LLM05 output schema check — opt-in, per-tool. Runs after the PII
	// filter (PII redaction may have rewritten string content; the
	// schema check then verifies the result still matches the declared
	// shape). Three actions, same vocabulary as PII:
	//
	//   - allow  → log violations only, forward unchanged
	//   - strip  → remove undeclared fields and wrong-type scalars,
	//              forward the cleaned response (DEFAULT)
	//   - block  → refuse the response, return -32016 to the caller
	//
	// When no schema is declared for this tool, the stage is a no-op.
	// Schemas are loaded from INTENTGATE_OUTPUT_SCHEMAS_PATH at startup;
	// per-tool action overrides take precedence over the registry's
	// default action.
	if h.cfg.OutputSchemas != nil && parsed.Result != nil {
		if schema, action, ok := h.cfg.OutputSchemas.Lookup(params.Name); ok {
			osRes := schema.Validate(parsed.Result)
			switch {
			case !osRes.HasViolations():
				h.cfg.Metrics.ObserveCheck("output_schema", "allow", time.Since(start))
				// No audit row on a clean response — same discipline as
				// PII and provenance.

			case action == outputschema.ActionBlock:
				h.cfg.Metrics.ObserveCheck("output_schema", "block", time.Since(start))
				h.emitAudit(ctx, r, params, cap, intent,
					audit.DecisionBlock, audit.CheckOutputSchema,
					fmt.Sprintf("output schema blocked response (kinds=%v)", osRes.CountsByKind()),
					start, upResp.Status,
					withRequiresStepUp(requiresStepUp))
				return mcp.NewErrorResponse(req.ID, mcp.CodeOutputSchemaViolation,
					"response blocked by output schema",
					map[string]any{
						"counts": osRes.CountsByKind(),
						"tool":   params.Name,
					})

			case action == outputschema.ActionStrip:
				parsed.Result = osRes.Stripped
				h.cfg.Metrics.ObserveCheck("output_schema", "redact", time.Since(start))
				h.emitAudit(ctx, r, params, cap, intent,
					audit.DecisionAllow, audit.CheckOutputSchema,
					fmt.Sprintf("output schema stripped response (kinds=%v)", osRes.CountsByKind()),
					start, upResp.Status,
					withRequiresStepUp(requiresStepUp))
				// fall through to inject metadata + return the cleaned response

			case action == outputschema.ActionAllow:
				h.cfg.Metrics.ObserveCheck("output_schema", "allow", time.Since(start))
				h.emitAudit(ctx, r, params, cap, intent,
					audit.DecisionAllow, audit.CheckOutputSchema,
					fmt.Sprintf("output schema violations logged (kinds=%v)", osRes.CountsByKind()),
					start, upResp.Status,
					withRequiresStepUp(requiresStepUp))
			}
		}
	}

	if parsed.Result != nil {
		parsed.Result = injectIntentGateMetadata(parsed.Result, mcp.IntentGateMetadata{
			Decision:  "allow",
			Reason:    "forwarded",
			LatencyMS: time.Since(start).Milliseconds(),
		})
	}

	h.emitAudit(ctx, r, params, cap, intent,
		audit.DecisionAllow, audit.CheckUpstream, "forwarded", start, upResp.Status,
		withRequiresStepUp(requiresStepUp))

	return &parsed
}

// handlePassthrough handles MCP discovery and lifecycle methods —
// tools/list, initialize, ping — that don't fit the four-check
// authorization pipeline (no tool name to evaluate). When an upstream
// is configured, the request is forwarded verbatim and the upstream's
// response is returned unchanged. When no upstream is configured, a
// minimal local response keeps an MCP handshake working against a
// standalone gateway:
//
//   - initialize  → advertises protocolVersion + serverInfo
//   - tools/list  → empty list (no upstream means no real tools)
//   - ping        → empty success
//
// No _intentgate metadata is injected (these aren't authorization
// decisions) and no audit event is emitted (audit is reserved for
// tools/call decisions; flooding it with handshake noise would dilute
// signal-to-noise for SOC analysts).
func (h *mcpHandler) handlePassthrough(ctx context.Context, req *mcp.Request, body []byte) *mcp.Response {
	if h.cfg.Upstream != nil {
		// Handshake passthrough (tools/list, ping) — no specific tool, so
		// only the global upstream credential applies (nil per-tool).
		upResp, err := h.cfg.Upstream.Forward(ctx, body, nil)
		if err != nil {
			var uerr *upstream.Error
			if errors.As(err, &uerr) {
				h.cfg.Logger.Warn("upstream passthrough failed",
					"method", req.Method,
					"kind", uerr.Kind.String(),
					"status", uerr.Status,
					"err", uerr.Error(),
				)
				return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
					"upstream "+uerr.Kind.String(),
					map[string]any{
						"upstream_status": uerr.Status,
						"detail":          uerr.Error(),
					})
			}
			return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
				"upstream error", err.Error())
		}

		var parsed mcp.Response
		if err := json.Unmarshal(upResp.Body, &parsed); err != nil {
			h.cfg.Logger.Error("upstream returned non-JSON-RPC body",
				"method", req.Method, "err", err)
			return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
				"upstream returned non-JSON-RPC body", err.Error())
		}
		return &parsed
	}

	// No upstream configured — return a minimal local response so an
	// MCP handshake against a stub-mode gateway still completes cleanly.
	switch req.Method {
	case mcp.MethodInitialize:
		resp, err := mcp.NewResultResponse(req.ID, mcp.InitializeResult{
			ProtocolVersion: "2025-03-26",
			ServerInfo: mcp.ServerInfo{
				Name:    "intentgate",
				Version: "0.2",
			},
			Capabilities: map[string]any{
				"tools": map[string]any{},
			},
		})
		if err != nil {
			return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
				"failed to encode initialize result", err.Error())
		}
		return resp

	case mcp.MethodToolsList:
		resp, err := mcp.NewResultResponse(req.ID, map[string]any{
			"tools": []any{},
		})
		if err != nil {
			return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
				"failed to encode tools/list result", err.Error())
		}
		return resp

	case mcp.MethodPing:
		resp, err := mcp.NewResultResponse(req.ID, map[string]any{})
		if err != nil {
			return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
				"failed to encode ping result", err.Error())
		}
		return resp
	}

	// Unreachable: ServeHTTP only dispatches the three methods above to
	// this handler. Defensive fallback in case the dispatch is widened.
	return mcp.NewErrorResponse(req.ID, mcp.CodeMethodNotFound,
		"method not implemented in passthrough: "+req.Method, nil)
}

// injectIntentGateMetadata adds (or replaces) the "_intentgate"
// vendor-extension field on the upstream's result object. If the
// result isn't a JSON object (unusual but legal), the original bytes
// are returned unchanged.
func injectIntentGateMetadata(result json.RawMessage, meta mcp.IntentGateMetadata) json.RawMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(result, &obj); err != nil {
		return result
	}
	encoded, err := json.Marshal(meta)
	if err != nil {
		return result
	}
	obj["_intentgate"] = encoded
	out, err := json.Marshal(obj)
	if err != nil {
		return result
	}
	return out
}

// capabilityCheckResult bundles what the capability stage learned.
type capabilityCheckResult struct {
	agentID string
	summary string
	// token is the verified token, retained so subsequent stages
	// (intent, policy, budget) can read its caveats. nil when no token
	// was supplied.
	token *capability.Token
	err   error
}

// intentCheckResult bundles what the intent stage learned.
type intentCheckResult struct {
	summary string                     // short description for logs
	intent  *extractor.ExtractedIntent // populated when extraction ran; nil if skipped
	err     error
}

// defaultApprovalTimeout is used when the operator did not set
// MCPHandlerConfig.ApprovalTimeout. Five minutes is a deliberate
// midpoint between "synchronous reviewers can keep up" and "agent
// HTTP clients won't drop the connection."
const defaultApprovalTimeout = 5 * time.Minute

// runApprovalFlow handles the escalate path. Returns a non-nil
// JSON-RPC response when the call should NOT proceed (queue
// misconfigured, enqueue error, rejected, timed out). Returns nil
// when the operator approved and the caller should resume the
// pipeline (continue to the budget check).
func (h *mcpHandler) runApprovalFlow(
	ctx context.Context,
	r *http.Request,
	req *mcp.Request,
	params *mcp.ToolCallParams,
	capResult capabilityCheckResult,
	intResult intentCheckResult,
	originCheck audit.Check,
	policyReason string,
	requiresStepUp bool,
	start time.Time,
) *mcp.Response {
	// No queue wired? Block. We refuse to silently allow a call the
	// policy specifically said needed human review.
	if h.cfg.Approvals == nil {
		reason := "escalation required but no approvals queue configured (set INTENTGATE_APPROVAL_QUEUE)"
		h.emitAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, originCheck, reason, start, 0,
			withRequiresStepUp(requiresStepUp))
		return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
			"policy escalation required", reason)
	}

	pending := approvals.PendingRequest{
		AgentID:        capResult.agentID,
		Tool:           params.Name,
		Args:           params.Arguments,
		IntentSummary:  intentSummary(intResult),
		Reason:         policyReason,
		RequiresStepUp: requiresStepUp,
	}
	if capResult.token != nil {
		pending.CapabilityTokenID = capResult.token.ID
		pending.RootCapabilityTokenID = capResult.token.RootID
		pending.Tenant = capResult.token.Tenant
	}

	row, err := h.cfg.Approvals.Enqueue(ctx, pending)
	if err != nil {
		reason := "approval queue: " + err.Error()
		h.cfg.Logger.Error("approval enqueue failed", "err", err, "tool", params.Name)
		h.emitAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, originCheck, reason, start, 0,
			withRequiresStepUp(requiresStepUp))
		return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
			"policy escalation failed", reason)
	}

	// Audit the escalation. PendingID lets SOC join this event with
	// the eventual approve / reject / timeout event.
	h.emitApprovalAudit(ctx, r, params, capResult, intResult,
		audit.DecisionEscalate, originCheck, "escalate: "+policyReason, row.PendingID, "", start,
		withRequiresStepUp(requiresStepUp))

	timeout := h.cfg.ApprovalTimeout
	if timeout <= 0 {
		timeout = defaultApprovalTimeout
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	final, werr := h.cfg.Approvals.Wait(waitCtx, row.PendingID)
	if werr != nil {
		reason := "approval wait: " + werr.Error()
		h.cfg.Logger.Error("approval wait failed", "err", werr, "pending_id", row.PendingID)
		h.emitApprovalAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, originCheck, reason, row.PendingID, "", start,
			withRequiresStepUp(requiresStepUp))
		return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
			"policy escalation failed", reason)
	}

	switch final.Status {
	case approvals.StatusApproved:
		// Audit the human approval as a CheckPolicy allow so the
		// SOC log shows the human-in-the-loop step. The pipeline
		// continues to budget and then upstream; that final
		// allow/forward emits its own audit too.
		reason := "approved by " + safeDecidedBy(final)
		if final.DecideNote != "" {
			reason += ": " + final.DecideNote
		}
		h.emitApprovalAudit(ctx, r, params, capResult, intResult,
			audit.DecisionAllow, originCheck, reason, row.PendingID, final.DecidedBy, start,
			withRequiresStepUp(requiresStepUp))
		h.cfg.Logger.Info("mcp tools/call approved by human",
			"tool", params.Name, "agent", capResult.agentID,
			"pending_id", row.PendingID, "by", final.DecidedBy)
		return nil

	case approvals.StatusRejected:
		reason := "rejected by " + safeDecidedBy(final)
		if final.DecideNote != "" {
			reason += ": " + final.DecideNote
		}
		h.emitApprovalAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, originCheck, reason, row.PendingID, final.DecidedBy, start,
			withRequiresStepUp(requiresStepUp))
		h.cfg.Logger.Info("mcp tools/call rejected by human",
			"tool", params.Name, "agent", capResult.agentID,
			"pending_id", row.PendingID, "by", final.DecidedBy)
		return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
			"policy: rejected by reviewer", reason)

	case approvals.StatusTimeout:
		reason := "approval window expired (" + timeout.String() + ")"
		h.emitApprovalAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, originCheck, reason, row.PendingID, "", start,
			withRequiresStepUp(requiresStepUp))
		h.cfg.Logger.Info("mcp tools/call approval timed out",
			"tool", params.Name, "agent", capResult.agentID,
			"pending_id", row.PendingID)
		return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
			"policy: approval window expired", reason)

	default:
		reason := "unexpected approval status: " + string(final.Status)
		h.emitApprovalAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, originCheck, reason, row.PendingID, "", start,
			withRequiresStepUp(requiresStepUp))
		return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
			"policy escalation failed", reason)
	}
}

// emitApprovalAudit is emitAudit with two extra fields populated
// (pending_id, decided_by). Lets the SOC analyst reconstruct an
// approval lifecycle by filtering on pending_id.
func (h *mcpHandler) emitApprovalAudit(
	ctx context.Context,
	r *http.Request,
	params *mcp.ToolCallParams,
	cap capabilityCheckResult,
	intent intentCheckResult,
	decision audit.Decision,
	originCheck audit.Check,
	reason string,
	pendingID string,
	decidedBy string,
	start time.Time,
	opts ...auditEmitOption,
) {
	if h.cfg.Audit == nil {
		return
	}

	argKeys := make([]string, 0, len(params.Arguments))
	for k := range params.Arguments {
		argKeys = append(argKeys, k)
	}

	e := audit.NewEvent(decision, params.Name)
	e.Check = originCheck
	e.Reason = reason
	e.AgentID = cap.agentID
	e.ArgKeys = argKeys
	e.ArgValues = audit.RedactArgs(params.Arguments, h.cfg.ArgRedaction)
	e.LatencyMS = time.Since(start).Milliseconds()
	e.RemoteIP = r.RemoteAddr
	e.PendingID = pendingID
	e.DecidedBy = decidedBy

	if cap.token != nil {
		e.CapabilityTokenID = cap.token.ID
		e.RootCapabilityTokenID = cap.token.RootID
		e.CaveatCount = cap.token.CaveatCount()
		e.Tenant = cap.token.Tenant
	}
	if intent.intent != nil {
		e.IntentSummary = intent.intent.Summary
	}

	for _, o := range opts {
		o(&e)
	}

	h.cfg.Audit.Emit(ctx, e)
}

// intentSummary returns the captured intent summary (or empty).
// Helper for runApprovalFlow's PendingRequest building.
func intentSummary(r intentCheckResult) string {
	if r.intent == nil {
		return ""
	}
	return r.intent.Summary
}

// safeDecidedBy returns the operator identity, or "(anonymous)" when
// blank — useful so the audit reason field is never an awkward
// "approved by ".
func safeDecidedBy(p approvals.PendingRequest) string {
	if p.DecidedBy == "" {
		return "(anonymous)"
	}
	return p.DecidedBy
}

// policyCheckResult bundles what the policy stage learned.
type policyCheckResult struct {
	summary  string // short description ("ok: <reason>", "skipped (no engine)", ...)
	err      error
	escalate bool   // policy returned {"escalate": true} — pause for human review
	reason   string // operator-readable reason (used as summary on escalate path)
	// requiresStepUp mirrors policy.Decision.RequiresStepUp. Carried
	// onto the audit event so SOC dashboards / the Pro console's
	// high-risk feed can surface calls that needed (or wanted) a
	// fresh step-up factor, regardless of whether the policy also
	// blocked them.
	requiresStepUp bool
	// piiOverride carries any per-request PII filter spec the policy
	// returned (Rego field `pii_filter`). When non-nil, the handler
	// uses this for the response-stream PII filter on this call
	// instead of the gateway's static config. Most policies leave
	// this nil; tenants who need per-tool overrides set it. See
	// policy.PIIFilterSpec and memos/llm02-pii-filter-design.md.
	piiOverride *policy.PIIFilterSpec
}

// budgetCheckResult bundles what the budget stage learned.
type budgetCheckResult struct {
	summary string // short description ("ok: 3/10 calls", "skipped", ...)
	err     error
}

// runCapabilityCheck verifies the Bearer token's HMAC chain, consults
// the revocation store, and evaluates the token's caveats against the
// requested tool. Returns the first failure; on success, the verified
// token (with subject filled in) is included in the result for later
// stages.
//
// Revocation is checked after signature verification but before caveat
// evaluation: if a genuine-but-revoked token is presented, the
// resulting error says "token revoked" rather than "tool not allowed",
// which is the more accurate audit story.
//
// A non-nil error from the revocation store fails closed (treats the
// token as revoked). A partial outage of the revocation store must
// not become a quiet authorization bypass.
func (h *mcpHandler) runCapabilityCheck(r *http.Request, tool string) capabilityCheckResult {
	encoded, err := capability.FromAuthorizationHeader(r.Header.Get("Authorization"))
	if err != nil {
		return capabilityCheckResult{err: err}
	}
	if encoded == "" {
		if h.cfg.RequireCapability {
			return capabilityCheckResult{err: errMissingCapability}
		}
		h.cfg.Logger.Warn("capability check skipped (no token)",
			"tool", tool,
			"hint", "set INTENTGATE_REQUIRE_CAPABILITY=true to enforce")
		return capabilityCheckResult{summary: "skipped (no token)"}
	}

	tok, err := capability.Decode(encoded)
	if err != nil {
		return capabilityCheckResult{err: err}
	}
	if err := tok.Verify(h.cfg.MasterKey); err != nil {
		return capabilityCheckResult{err: err}
	}

	// Kill switch runs before revocation: it is the operator's circuit
	// breaker for whole classes of traffic (this agent, this tenant, or
	// everything), independent of any specific token's JTI. Like
	// revocation, a store error fails closed — an engaged breaker must
	// not be silently bypassed by a store outage.
	if h.cfg.KillSwitch != nil {
		halted, entry, kerr := h.cfg.KillSwitch.Active(r.Context(), tok.Tenant, tok.Subject)
		switch {
		case kerr != nil:
			h.cfg.Logger.Error("kill-switch lookup failed; failing closed",
				"jti", tok.ID, "err", kerr)
			return capabilityCheckResult{
				agentID: tok.Subject,
				token:   tok,
				err:     capError("kill switch store unavailable; request halted (fail-closed)"),
			}
		case halted:
			h.cfg.Logger.Warn("request halted by kill switch",
				"scope", entry.Type, "tenant", entry.Tenant,
				"agent", entry.Value, "reason", entry.Reason)
			return capabilityCheckResult{
				agentID: tok.Subject,
				token:   tok,
				err:     capError("halted by kill switch (" + string(entry.Type) + ")"),
			}
		}
	}

	if h.cfg.Revocation != nil {
		revStart := time.Now()
		// Pass the verified token's tenant so the revocation lookup
		// is scoped: a per-tenant admin's revocation only affects
		// their own tenant; a superadmin revocation (tenant="") still
		// applies globally because the store matches both rows.
		revoked, rerr := h.cfg.Revocation.IsRevoked(r.Context(), tok.ID, tok.Tenant)
		revDur := time.Since(revStart)
		switch {
		case rerr != nil:
			h.cfg.Metrics.ObserveRevocation("error", revDur)
			h.cfg.Logger.Error("revocation lookup failed; failing closed",
				"jti", tok.ID, "err", rerr)
			return capabilityCheckResult{
				agentID: tok.Subject,
				token:   tok,
				err:     capError("revocation store unavailable; token rejected (fail-closed)"),
			}
		case revoked:
			h.cfg.Metrics.ObserveRevocation("revoked", revDur)
			return capabilityCheckResult{
				agentID: tok.Subject,
				token:   tok,
				err:     capError("token revoked"),
			}
		default:
			h.cfg.Metrics.ObserveRevocation("not_revoked", revDur)
		}
	}

	if err := tok.Check(capability.RequestContext{
		AgentID: tok.Subject,
		Tool:    tool,
	}); err != nil {
		return capabilityCheckResult{agentID: tok.Subject, token: tok, err: err}
	}
	return capabilityCheckResult{agentID: tok.Subject, token: tok, summary: "ok"}
}

// runIntentCheck reads the X-Intent-Prompt header and asks the
// extractor for structured intent, then verifies the requested tool
// is permitted by that intent.
//
// Three outcome categories:
//
//   - Header present, extractor configured → call extractor, enforce.
//   - Header missing, RequireIntent false  → skip (dev mode default).
//   - Header missing, RequireIntent true   → fail closed.
//   - Extractor unconfigured               → skip (gateway in standalone mode).
func (h *mcpHandler) runIntentCheck(ctx context.Context, r *http.Request, tool, agentID string) intentCheckResult {
	prompt := r.Header.Get("X-Intent-Prompt")
	if prompt == "" {
		if h.cfg.RequireIntent {
			return intentCheckResult{err: errMissingIntent}
		}
		return intentCheckResult{summary: "skipped (no prompt header)"}
	}
	if h.cfg.Extractor == nil {
		if h.cfg.RequireIntent {
			return intentCheckResult{err: errExtractorNotConfigured}
		}
		h.cfg.Logger.Warn("intent header present but no extractor configured",
			"tool", tool,
			"hint", "set INTENTGATE_EXTRACTOR_URL to enable intent enforcement")
		return intentCheckResult{summary: "skipped (no extractor configured)"}
	}

	intent, err := h.cfg.Extractor.Extract(ctx, prompt, agentID)
	if err != nil {
		// Failing the extractor means we don't know the intent. Fail closed.
		return intentCheckResult{err: err}
	}
	ok, reason := intent.Allows(tool)
	if !ok {
		return intentCheckResult{intent: intent, err: capError(reason)}
	}
	return intentCheckResult{intent: intent, summary: "ok: " + reason}
}

// runPolicyCheck evaluates the Rego policy bundled into (or supplied to)
// the gateway. The policy sees the requested tool, its arguments, the
// agent ID from the verified capability token, and — when intent
// extraction ran — the extractor's structured output.
//
// When no engine is configured, the check is skipped (dev convenience).
// In production, main.go always supplies an engine: either a customer-
// authored policy from INTENTGATE_POLICY_FILE or the embedded default.
func (h *mcpHandler) runPolicyCheck(
	ctx context.Context,
	params *mcp.ToolCallParams,
	cap capabilityCheckResult,
	intent intentCheckResult,
) policyCheckResult {
	if h.cfg.Policy == nil {
		return policyCheckResult{summary: "skipped (no policy engine)"}
	}

	in := policy.Input{
		Tool:    params.Name,
		Args:    params.Arguments,
		AgentID: cap.agentID,
	}
	if cap.agentID != "" || cap.token != nil {
		in.Capability = &policy.InputCap{Subject: cap.agentID}
		if cap.token != nil {
			// Tenant on the input drives the Reloader's per-tenant
			// dispatch — a request from tenant=acme evaluates
			// against acme's promoted engine, falling back to the
			// default-fallback engine when acme has no slot.
			in.Capability.Tenant = cap.token.Tenant
			// Zone lets policy gate north-south access by the caller's
			// signed segmentation zone, alongside the zone-scope guard.
			in.Capability.Zone = cap.token.Zone
			// StepUpAt is sourced from the signed step_up caveat on
			// the token's chain (set by /v1/admin/mint when the
			// operator confirmed an out-of-band factor). A token
			// with no step_up caveat leaves the field at zero, which
			// is what Rego policies treat as "no fresh factor on
			// record." The most-recent caveat wins on the rare case
			// a delegation chain stamped multiple step-ups.
			for _, c := range cap.token.Caveats {
				if c.Type == capability.CaveatStepUp && c.StepUpAt > in.Capability.StepUpAt {
					in.Capability.StepUpAt = c.StepUpAt
				}
			}
		}
	}
	if intent.intent != nil {
		in.Intent = &policy.InputIntent{
			Summary:        intent.intent.Summary,
			AllowedTools:   intent.intent.AllowedTools,
			ForbiddenTools: intent.intent.ForbiddenTools,
			Confidence:     intent.intent.Confidence,
		}
	}
	// East-west shape: when this call is an agent-to-agent call, surface the
	// caller, callee, and their zones so policy can condition the specific
	// edge. Uses the same guard resolution as the default-deny zone gate, so
	// the zones match. Nil for ordinary agent-to-tool calls.
	if h.cfg.EastWest != nil {
		var czone string
		if cap.token != nil {
			czone = cap.token.Zone
		}
		if ewRes := h.cfg.EastWest.Check(cap.agentID, czone, params.Name); ewRes.EastWest {
			in.EastWest = &policy.InputEastWest{
				CallerAgent: ewRes.CallerAgent,
				CallerZone:  ewRes.CallerZone,
				CalleeAgent: ewRes.CalleeAgent,
				CalleeZone:  ewRes.CalleeZone,
			}
		}
	}

	d, err := h.cfg.Policy.Evaluate(ctx, in)
	if err != nil {
		// Engine failure = fail closed.
		return policyCheckResult{err: err}
	}
	// Escalate beats both allow and block: a high-risk rule fired,
	// no autopilot. The mcp handler surfaces this to the approvals
	// queue and pauses.
	if d.Escalate {
		return policyCheckResult{
			escalate:       true,
			reason:         d.Reason,
			summary:        "escalate: " + d.Reason,
			requiresStepUp: d.RequiresStepUp,
			piiOverride:    d.PIIFilter,
		}
	}
	if !d.Allow {
		return policyCheckResult{err: capError(d.Reason), requiresStepUp: d.RequiresStepUp}
	}
	if d.Reason != "" {
		return policyCheckResult{summary: "ok: " + d.Reason, requiresStepUp: d.RequiresStepUp, piiOverride: d.PIIFilter}
	}
	return policyCheckResult{summary: "ok", requiresStepUp: d.RequiresStepUp, piiOverride: d.PIIFilter}
}

// runBudgetCheck increments the per-token call counter and verifies
// the new total against any max_calls caveats present in the verified
// token.
//
// Behavior table:
//
//   - No verified token, RequireBudget=false → skipped (dev mode).
//   - No verified token, RequireBudget=true  → fail closed.
//   - Token present, no max_calls caveat     → allow without touching the store.
//   - Token present, max_calls exceeded      → deny with the strictest cap's reason.
//   - Token present, store nil but caveat ex → fail closed (operator misconfig).
func (h *mcpHandler) runBudgetCheck(ctx context.Context, cap capabilityCheckResult) budgetCheckResult {
	if cap.token == nil {
		if h.cfg.RequireBudget {
			return budgetCheckResult{err: errMissingBudgetToken}
		}
		return budgetCheckResult{summary: "skipped (no token)"}
	}
	d, err := budget.Check(ctx, h.cfg.Budget, cap.token)
	if err != nil {
		return budgetCheckResult{err: err}
	}
	if !d.Allowed {
		return budgetCheckResult{err: capError(d.Reason)}
	}
	if d.Used > 0 {
		return budgetCheckResult{summary: fmt.Sprintf("ok: %d call(s)", d.Used)}
	}
	return budgetCheckResult{summary: d.Reason}
}

// emitAudit builds and emits one audit event for the current request.
// Called exactly once per decision: at every block path and at the
// final allow path.
//
// The helper consolidates field gathering so each call site only has
// to specify what's specific to its decision (decision, check, reason).
// Everything else is plucked from the in-flight request and the
// partial check results.
func (h *mcpHandler) emitAudit(
	ctx context.Context,
	r *http.Request,
	params *mcp.ToolCallParams,
	cap capabilityCheckResult,
	intent intentCheckResult,
	decision audit.Decision,
	check audit.Check,
	reason string,
	start time.Time,
	upstreamStatus int,
	opts ...auditEmitOption,
) {
	if h.cfg.Audit == nil {
		return
	}

	argKeys := make([]string, 0, len(params.Arguments))
	for k := range params.Arguments {
		argKeys = append(argKeys, k)
	}

	e := audit.NewEvent(decision, params.Name)
	e.Check = check
	e.Reason = reason
	e.AgentID = cap.agentID
	e.ArgKeys = argKeys
	e.ArgValues = audit.RedactArgs(params.Arguments, h.cfg.ArgRedaction)
	e.LatencyMS = time.Since(start).Milliseconds()
	e.RemoteIP = r.RemoteAddr
	e.UpstreamStatus = upstreamStatus

	if cap.token != nil {
		e.CapabilityTokenID = cap.token.ID
		e.RootCapabilityTokenID = cap.token.RootID
		e.CaveatCount = cap.token.CaveatCount()
		e.Tenant = cap.token.Tenant
	}
	if intent.intent != nil {
		e.IntentSummary = intent.intent.Summary
	}

	// Apply optional annotations (requires_step_up, future fields).
	// Variadic options keep the call sites that don't need them
	// looking exactly the same as before.
	for _, o := range opts {
		o(&e)
	}

	h.cfg.Audit.Emit(ctx, e)
}

// auditEmitOption tweaks the audit event after the standard fields
// land but before it's emitted. Used so the policy stage can attach
// `requires_step_up` without ballooning emitAudit's positional signature.
type auditEmitOption func(*audit.Event)

// withRequiresStepUp returns an [auditEmitOption] that flips the
// requires_step_up flag on an event when the Rego policy stage said so.
// No-op when the flag is false, so call sites can pass it unconditionally.
func withRequiresStepUp(b bool) auditEmitOption {
	return func(e *audit.Event) {
		if b {
			e.RequiresStepUp = true
		}
	}
}

// checkDecision maps a (err, summary) pair from one of the runX
// helpers to the bounded decision label used by Prometheus. Anything
// with a non-nil error is "block"; an empty summary is "skip"
// (the check was disabled / not applicable); otherwise "allow".
func checkDecision(err error, summary string) string {
	if err != nil {
		return "block"
	}
	if strings.HasPrefix(summary, "skipped") {
		return "skip"
	}
	return "allow"
}

// errMissingCapability is the static error returned when a token is
// required but absent.
var (
	errMissingCapability      = capError("capability token required (INTENTGATE_REQUIRE_CAPABILITY=true)")
	errMissingIntent          = capError("intent prompt required (INTENTGATE_REQUIRE_INTENT=true)")
	errExtractorNotConfigured = capError("intent prompt provided but no extractor URL is configured")
	errMissingBudgetToken     = capError("budget enforcement requires a verified capability token")
)

// capError is a tiny error type so we don't pull in fmt for one string.
type capError string

func (e capError) Error() string { return string(e) }

// requestPIIFilter resolves which pii.Filter to apply to the OUTBOUND
// request arguments. Three-tier fallback identical to the response-
// side path: per-request Rego override → static gateway filter → no
// filter. Returns nil when nothing should run (which also makes the
// caller a no-op).
//
// Building the filter for each request is cheap (the detector caches
// compiled regexes and the FilterSpec → Filter conversion is a tiny
// allocation) but worth factoring so the request-side call site stays
// readable.
func (h *mcpHandler) requestPIIFilter(override *policy.PIIFilterSpec, agentID, toolName string) *pii.Filter {
	if override != nil {
		f, err := pii.NewFilterFromSpec(pii.FilterSpec{
			Enabled:          override.Enabled,
			Patterns:         override.Patterns,
			DefaultAction:    override.DefaultAction,
			PerPatternAction: override.PerPatternAction,
			CustomPatterns:   piiOverrideToCustomPatterns(override.CustomPatterns),
		})
		if err == nil {
			return f
		}
		h.cfg.Logger.Warn("pii filter override invalid; falling back to static config",
			"agent", agentID, "tool", toolName, "err", err, "direction", "request")
	}
	return h.cfg.PIIFilter
}

// piiOverrideToCustomPatterns adapts the policy package's
// PIIFilterCustomPattern shape to the pii package's
// FilterSpecCustomPattern shape so neither package has to import the
// other. The two structs are intentionally type-equivalent but kept
// separate to keep the import graph one-directional (handlers depends
// on both policy and pii; policy and pii don't depend on each other).
func piiOverrideToCustomPatterns(in []policy.PIIFilterCustomPattern) []pii.FilterSpecCustomPattern {
	if len(in) == 0 {
		return nil
	}
	out := make([]pii.FilterSpecCustomPattern, 0, len(in))
	for _, p := range in {
		out = append(out, pii.FilterSpecCustomPattern{
			Class: p.Class,
			Regex: p.Regex,
		})
	}
	return out
}

// write encodes a JSON-RPC response.
func (h *mcpHandler) write(w http.ResponseWriter, resp *mcp.Response) {
	if resp == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.cfg.Logger.Error("failed to encode mcp response", "err", err)
	}
}
