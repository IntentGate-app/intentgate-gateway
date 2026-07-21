package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/IntentGate-app/intentgate-gateway/internal/policystore"
)

// Separation of duties at the API boundary.
//
// The store tests hold the property; these hold the contract around
// it — the status codes an operator and a console actually see, and
// the guarantee that a refused approval leaves the live policy alone.
// A 200 with the old policy still running would be as bad as a wrong
// promote, because the console would report a change that did not
// happen.

func seedDraft(t *testing.T, store *policystore.MemoryStore, src string) policystore.Draft {
	t.Helper()
	d, err := store.CreateDraft(context.Background(), policystore.Draft{
		Name:       "candidate",
		RegoSource: src,
	})
	if err != nil {
		t.Fatalf("seed draft: %v", err)
	}
	return d
}

func TestApproveHandler_RefusesSelfApprovalWith409(t *testing.T) {
	cfg, store, reloader := newPolicyAdminCfg(t)
	d := seedDraft(t, store, policyTestRegoV2)

	rr := doReq(t, NewAdminProposeHandler(cfg), http.MethodPost,
		"/v1/admin/policies/propose", "super",
		map[string]any{"draft_id": d.ID, "proposed_by": "alice@example.com"}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("propose: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = doReq(t, NewAdminApproveHandler(cfg), http.MethodPost,
		"/v1/admin/policies/approve", "super",
		map[string]any{"acted_by": "alice@example.com"}, nil)
	if rr.Code != http.StatusConflict {
		t.Fatalf("self-approval: want 409, got %d: %s", rr.Code, rr.Body.String())
	}

	// The live engine must be untouched. This is the assertion that
	// matters: a refusal that still swapped the policy would mean the
	// control reported failure while doing the thing anyway.
	active, err := store.GetActive(context.Background(), "")
	if err != nil {
		t.Fatalf("get active: %v", err)
	}
	if active.CurrentDraftID != "" {
		t.Errorf("refused approval still promoted: %+v", active)
	}
	if reloader == nil {
		t.Fatal("reloader missing")
	}
}

func TestApproveHandler_SecondOperatorPromotesAndSwaps(t *testing.T) {
	cfg, store, _ := newPolicyAdminCfg(t)
	d := seedDraft(t, store, policyTestRegoV2)

	if rr := doReq(t, NewAdminProposeHandler(cfg), http.MethodPost,
		"/v1/admin/policies/propose", "super",
		map[string]any{"draft_id": d.ID, "proposed_by": "alice@example.com"}, nil,
	); rr.Code != http.StatusOK {
		t.Fatalf("propose: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var out struct {
		Swapped bool               `json:"swapped"`
		Active  policystore.Active `json:"active"`
	}
	rr := doReq(t, NewAdminApproveHandler(cfg), http.MethodPost,
		"/v1/admin/policies/approve", "super",
		map[string]any{"acted_by": "bob@example.com"}, &out)
	if rr.Code != http.StatusOK {
		t.Fatalf("approve: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !out.Swapped {
		t.Error("approve reported no engine swap")
	}
	if out.Active.CurrentDraftID != d.ID {
		t.Errorf("wrong draft live: %+v", out.Active)
	}
	if out.Active.PromotedBy != "alice@example.com" || out.Active.ApprovedBy != "bob@example.com" {
		t.Errorf("both operators must appear, and the right way round: %+v", out.Active)
	}
}

// Proposing does not change what the gateway is running. If it did,
// the review step would be decorative.
func TestProposeHandler_DoesNotChangeTheLivePolicy(t *testing.T) {
	cfg, store, _ := newPolicyAdminCfg(t)
	d := seedDraft(t, store, policyTestRegoV2)

	var out struct {
		Swapped bool `json:"swapped"`
	}
	rr := doReq(t, NewAdminProposeHandler(cfg), http.MethodPost,
		"/v1/admin/policies/propose", "super",
		map[string]any{"draft_id": d.ID, "proposed_by": "alice@example.com"}, &out)
	if rr.Code != http.StatusOK {
		t.Fatalf("propose: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if out.Swapped {
		t.Error("a proposal swapped the live engine")
	}
	active, _ := store.GetActive(context.Background(), "")
	if active.CurrentDraftID != "" {
		t.Errorf("a proposal promoted a draft: %+v", active)
	}
	if active.ProposedDraftID != d.ID {
		t.Errorf("proposal not recorded: %+v", active)
	}
}

// Rego that does not compile is caught at propose time, not left for
// the approver to discover. Otherwise a proposal sits in the queue
// looking ready when it could never have gone live.
func TestProposeHandler_RejectsUncompilableRego(t *testing.T) {
	cfg, store, _ := newPolicyAdminCfg(t)
	d := seedDraft(t, store, "package intentgate.policy\nthis is not rego{{{")

	rr := doReq(t, NewAdminProposeHandler(cfg), http.MethodPost,
		"/v1/admin/policies/propose", "super",
		map[string]any{"draft_id": d.ID, "proposed_by": "alice@example.com"}, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad rego, got %d: %s", rr.Code, rr.Body.String())
	}
	active, _ := store.GetActive(context.Background(), "")
	if active.ProposedDraftID != "" {
		t.Errorf("uncompilable draft was recorded as pending: %+v", active)
	}
}

func TestProposeHandler_RequiresANamedProposer(t *testing.T) {
	cfg, store, _ := newPolicyAdminCfg(t)
	d := seedDraft(t, store, policyTestRegoV2)

	rr := doReq(t, NewAdminProposeHandler(cfg), http.MethodPost,
		"/v1/admin/policies/propose", "super",
		map[string]any{"draft_id": d.ID, "proposed_by": "   "}, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for blank proposer, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestApproveHandler_NothingPendingIs404(t *testing.T) {
	cfg, _, _ := newPolicyAdminCfg(t)
	rr := doReq(t, NewAdminApproveHandler(cfg), http.MethodPost,
		"/v1/admin/policies/approve", "super",
		map[string]any{"acted_by": "bob@example.com"}, nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestRejectHandler_ClearsWithoutPromoting(t *testing.T) {
	cfg, store, _ := newPolicyAdminCfg(t)
	d := seedDraft(t, store, policyTestRegoV2)

	if rr := doReq(t, NewAdminProposeHandler(cfg), http.MethodPost,
		"/v1/admin/policies/propose", "super",
		map[string]any{"draft_id": d.ID, "proposed_by": "alice@example.com"}, nil,
	); rr.Code != http.StatusOK {
		t.Fatalf("propose: %d", rr.Code)
	}

	// The proposer withdrawing their own request is allowed.
	rr := doReq(t, NewAdminRejectHandler(cfg), http.MethodPost,
		"/v1/admin/policies/reject", "super",
		map[string]any{"acted_by": "alice@example.com"}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("reject: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	active, _ := store.GetActive(context.Background(), "")
	if active.ProposedDraftID != "" || active.CurrentDraftID != "" {
		t.Errorf("reject should clear and promote nothing: %+v", active)
	}
}

// With RequireApproval on, the direct promote path is closed. Without
// this the whole flow is optional in practice: anyone who found it
// inconvenient would call the old endpoint instead.
func TestPromoteHandler_ClosedWhenApprovalRequired(t *testing.T) {
	cfg, store, _ := newPolicyAdminCfg(t)
	cfg.RequireApproval = true
	d := seedDraft(t, store, policyTestRegoV2)

	rr := doReq(t, NewAdminPromoteHandler(cfg), http.MethodPost,
		"/v1/admin/policies/active", "super",
		map[string]any{"draft_id": d.ID, "promoted_by": "alice@example.com"}, nil)
	if rr.Code != http.StatusConflict {
		t.Fatalf("want 409 when approval is required, got %d: %s", rr.Code, rr.Body.String())
	}
	active, _ := store.GetActive(context.Background(), "")
	if active.CurrentDraftID != "" {
		t.Errorf("direct promote succeeded despite the requirement: %+v", active)
	}
}

// And with the flag off, the old path keeps working. Existing
// deployments automate this call; breaking it at upgrade would get
// the feature switched off rather than adopted.
func TestPromoteHandler_OpenByDefault(t *testing.T) {
	cfg, store, _ := newPolicyAdminCfg(t)
	d := seedDraft(t, store, policyTestRegoV2)

	rr := doReq(t, NewAdminPromoteHandler(cfg), http.MethodPost,
		"/v1/admin/policies/active", "super",
		map[string]any{"draft_id": d.ID, "promoted_by": "alice@example.com"}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 with approval not required, got %d: %s", rr.Code, rr.Body.String())
	}
	active, _ := store.GetActive(context.Background(), "")
	if active.CurrentDraftID != d.ID {
		t.Errorf("promote did not take effect: %+v", active)
	}
	if active.ApprovedBy != "" {
		t.Errorf("an unapproved promote recorded an approver: %q", active.ApprovedBy)
	}
}

// The console renders "this gateway requires a second approver" from
// this field. If it were wrong, the console would be making a false
// assurance about a security control, which is worse than saying
// nothing at all.
func TestActiveGet_ReportsWhetherApprovalIsRequired(t *testing.T) {
	for _, required := range []bool{false, true} {
		cfg, _, _ := newPolicyAdminCfg(t)
		cfg.RequireApproval = required

		var out struct {
			RequiresApproval bool `json:"requires_approval"`
		}
		rr := doReq(t, NewAdminActiveGetHandler(cfg, "embedded"), http.MethodGet,
			"/v1/admin/policies/active", "super", nil, &out)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		if out.RequiresApproval != required {
			t.Errorf("RequireApproval=%v reported as %v", required, out.RequiresApproval)
		}
	}
}

// The pending draft is resolved server-side so the console can name
// what is waiting without a second round-trip.
func TestActiveGet_ResolvesTheProposedDraft(t *testing.T) {
	cfg, store, _ := newPolicyAdminCfg(t)
	d := seedDraft(t, store, policyTestRegoV2)

	if rr := doReq(t, NewAdminProposeHandler(cfg), http.MethodPost,
		"/v1/admin/policies/propose", "super",
		map[string]any{"draft_id": d.ID, "proposed_by": "alice@example.com"}, nil,
	); rr.Code != http.StatusOK {
		t.Fatalf("propose: %d", rr.Code)
	}

	var out struct {
		ProposedDraft *policystore.Draft `json:"proposed_draft"`
		Active        policystore.Active `json:"active"`
	}
	rr := doReq(t, NewAdminActiveGetHandler(cfg, "embedded"), http.MethodGet,
		"/v1/admin/policies/active", "super", nil, &out)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if out.ProposedDraft == nil || out.ProposedDraft.ID != d.ID {
		t.Fatalf("proposed draft not resolved: %+v", out.ProposedDraft)
	}
	if out.Active.ProposedBy != "alice@example.com" {
		t.Errorf("proposer not reported: %+v", out.Active)
	}
}

// A per-tenant admin cannot act on another tenant's policy slot.
func TestApprovalFlow_TenantScoping(t *testing.T) {
	cfg, store, _ := newPolicyAdminCfg(t)
	d, err := store.CreateDraft(context.Background(), policystore.Draft{
		Name: "acme candidate", RegoSource: policyTestRegoV2, Tenant: "acme",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	rr := doReq(t, NewAdminProposeHandler(cfg), http.MethodPost,
		"/v1/admin/policies/propose", "acme-tok",
		map[string]any{"draft_id": d.ID, "proposed_by": "alice@acme.example", "tenant": "globex"}, nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant propose: want 403, got %d: %s", rr.Code, rr.Body.String())
	}

	// Globex's admin cannot see acme's draft at all.
	rr = doReq(t, NewAdminProposeHandler(cfg), http.MethodPost,
		"/v1/admin/policies/propose", "globex-tok",
		map[string]any{"draft_id": d.ID, "proposed_by": "carol@globex.example"}, nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("foreign draft: want 404, got %d: %s", rr.Code, rr.Body.String())
	}
}
