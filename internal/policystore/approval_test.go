package policystore

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// Separation of duties on policy promotion.
//
// The property these tests hold in place is one sentence: the operator
// who proposes a policy cannot be the operator who puts it into
// production. Everything else here — the pending columns, the
// timestamps, the audit label — is bookkeeping around that one check.
// Without it the console has a workflow that looks like change control
// and isn't, which is worse than not having one, because somebody will
// point at it in an audit.

func mustDraft(t *testing.T, s *MemoryStore, name string) Draft {
	t.Helper()
	d, err := s.CreateDraft(context.Background(), Draft{
		Name:       name,
		RegoSource: "package intentgate\n\ndefault allow = false\n",
	})
	if err != nil {
		t.Fatalf("create draft: %v", err)
	}
	return d
}

func TestApproveRequiresADifferentOperator(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	d := mustDraft(t, s, "tighten prod db access")

	if _, err := s.Propose(ctx, d.ID, "alice@example.com", ""); err != nil {
		t.Fatalf("propose: %v", err)
	}

	if _, err := s.Approve(ctx, "alice@example.com", ""); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("alice approved her own proposal: err = %v", err)
	}

	// And the policy did not move.
	a, err := s.GetActive(ctx, "")
	if err != nil {
		t.Fatalf("get active: %v", err)
	}
	if a.CurrentDraftID != "" {
		t.Fatalf("a rejected self-approval still promoted the draft: %+v", a)
	}
	if a.ProposedDraftID != d.ID {
		t.Errorf("the proposal should survive a refused approval, got %q", a.ProposedDraftID)
	}
}

func TestApproveBySecondOperatorPromotes(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	d := mustDraft(t, s, "tighten prod db access")

	if _, err := s.Propose(ctx, d.ID, "alice@example.com", ""); err != nil {
		t.Fatalf("propose: %v", err)
	}
	got, err := s.Approve(ctx, "bob@example.com", "")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	if got.CurrentDraftID != d.ID {
		t.Errorf("approved draft did not become current: %+v", got)
	}
	// Both names, and the right way round. The proposer authored the
	// change; the approver signed it off. Collapsing them to one field
	// would lose exactly the fact that two people were involved.
	if got.PromotedBy != "alice@example.com" {
		t.Errorf("proposer lost from the record: PromotedBy = %q", got.PromotedBy)
	}
	if got.ApprovedBy != "bob@example.com" {
		t.Errorf("approver not recorded: ApprovedBy = %q", got.ApprovedBy)
	}
	if got.ProposedDraftID != "" {
		t.Errorf("proposal not cleared after approval: %q", got.ProposedDraftID)
	}
}

// An anonymous operator on either side makes the record meaningless:
// two blank names are indistinguishable from one blank name, so the
// row could not show that two people were involved.
func TestAnonymousProposeAndApproveAreRefused(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	d := mustDraft(t, s, "x")

	if _, err := s.Propose(ctx, d.ID, "", ""); !errors.Is(err, ErrUnidentified) {
		t.Fatalf("anonymous propose accepted: %v", err)
	}
	if _, err := s.Propose(ctx, d.ID, "alice@example.com", ""); err != nil {
		t.Fatalf("propose: %v", err)
	}
	if _, err := s.Approve(ctx, "", ""); !errors.Is(err, ErrUnidentified) {
		t.Fatalf("anonymous approve accepted: %v", err)
	}
}

func TestApproveWithNothingPending(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	if _, err := s.Approve(ctx, "bob@example.com", ""); !errors.Is(err, ErrNoProposal) {
		t.Fatalf("approve with nothing pending: %v", err)
	}
}

func TestProposeUnknownDraft(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	if _, err := s.Propose(ctx, "no-such-draft", "alice@example.com", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("proposed a draft that does not exist: %v", err)
	}
}

// Re-proposing replaces the pending request, including its proposer.
// The interesting case is the one that follows: the operator who made
// the FIRST proposal may approve the second, because they did not
// author it.
func TestReproposeReplacesTheProposer(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	first := mustDraft(t, s, "first")
	second := mustDraft(t, s, "second")

	if _, err := s.Propose(ctx, first.ID, "alice@example.com", ""); err != nil {
		t.Fatalf("propose first: %v", err)
	}
	if _, err := s.Propose(ctx, second.ID, "bob@example.com", ""); err != nil {
		t.Fatalf("propose second: %v", err)
	}

	if _, err := s.Approve(ctx, "bob@example.com", ""); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("bob approved the proposal he just replaced it with: %v", err)
	}
	got, err := s.Approve(ctx, "alice@example.com", "")
	if err != nil {
		t.Fatalf("alice should be able to approve bob's proposal: %v", err)
	}
	if got.CurrentDraftID != second.ID {
		t.Errorf("wrong draft promoted: got %q, want %q", got.CurrentDraftID, second.ID)
	}
}

func TestRejectClearsWithoutPromoting(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	d := mustDraft(t, s, "x")

	if _, err := s.Propose(ctx, d.ID, "alice@example.com", ""); err != nil {
		t.Fatalf("propose: %v", err)
	}
	// The proposer withdrawing their own request is allowed.
	got, err := s.RejectProposal(ctx, "alice@example.com", "")
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if got.ProposedDraftID != "" || got.CurrentDraftID != "" {
		t.Fatalf("reject should clear the proposal and promote nothing: %+v", got)
	}
	if _, err := s.RejectProposal(ctx, "alice@example.com", ""); !errors.Is(err, ErrNoProposal) {
		t.Fatalf("second reject should report nothing pending: %v", err)
	}
}

// A direct Promote is still available (deployments that have not
// turned on the approval requirement rely on it), but it must not
// inherit an approver. Otherwise a policy nobody reviewed shows the
// last reviewer's name against it.
func TestDirectPromoteClearsTheApprover(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	approved := mustDraft(t, s, "approved one")
	direct := mustDraft(t, s, "direct one")

	if _, err := s.Propose(ctx, approved.ID, "alice@example.com", ""); err != nil {
		t.Fatalf("propose: %v", err)
	}
	if _, err := s.Approve(ctx, "bob@example.com", ""); err != nil {
		t.Fatalf("approve: %v", err)
	}

	got, err := s.Promote(ctx, direct.ID, "carol@example.com", "")
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if got.ApprovedBy != "" {
		t.Errorf("an unapproved promote carries an approver's name: %q", got.ApprovedBy)
	}
	if got.PromotedBy != "carol@example.com" {
		t.Errorf("promoter not recorded: %q", got.PromotedBy)
	}
}

// A pending proposal is a record of what someone asked for. A third
// operator promoting something else does not withdraw that request.
func TestPromoteLeavesAPendingProposalAlone(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	pending := mustDraft(t, s, "pending")
	other := mustDraft(t, s, "other")

	if _, err := s.Propose(ctx, pending.ID, "alice@example.com", ""); err != nil {
		t.Fatalf("propose: %v", err)
	}
	got, err := s.Promote(ctx, other.ID, "carol@example.com", "")
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if got.ProposedDraftID != pending.ID || got.ProposedBy != "alice@example.com" {
		t.Fatalf("an unrelated promote discarded a pending proposal: %+v", got)
	}
}

// Rollback must not restore an approver. The store keeps one approval,
// attached to what is live, not an approval per version.
func TestRollbackDoesNotRestoreAnApprover(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	first := mustDraft(t, s, "first")
	second := mustDraft(t, s, "second")

	if _, err := s.Propose(ctx, first.ID, "alice@example.com", ""); err != nil {
		t.Fatalf("propose first: %v", err)
	}
	if _, err := s.Approve(ctx, "bob@example.com", ""); err != nil {
		t.Fatalf("approve first: %v", err)
	}
	if _, err := s.Propose(ctx, second.ID, "alice@example.com", ""); err != nil {
		t.Fatalf("propose second: %v", err)
	}
	if _, err := s.Approve(ctx, "bob@example.com", ""); err != nil {
		t.Fatalf("approve second: %v", err)
	}

	got, err := s.Rollback(ctx, "carol@example.com", "")
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got.CurrentDraftID != first.ID {
		t.Fatalf("rollback landed on the wrong draft: %q", got.CurrentDraftID)
	}
	if got.ApprovedBy != "" {
		t.Errorf("rollback invented an approver for the restored version: %q", got.ApprovedBy)
	}
}

// The JSON shape matters because the console renders straight from it.
// A zero proposed_at leaking through as "0001-01-01" would be shown as
// a proposal made in the year 1.
func TestActiveJSONElidesZeroTimestamps(t *testing.T) {
	raw, err := json.Marshal(Active{Tenant: "acme"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["promoted_at"]; ok {
		t.Errorf("zero promoted_at present in JSON: %s", raw)
	}
	if _, ok := m["proposed_at"]; ok {
		t.Errorf("zero proposed_at present in JSON: %s", raw)
	}
	// The earlier hand-rolled marshaller dropped any field it had not
	// been told about whenever promoted_at was zero. This is the guard
	// against that returning: tenant must survive.
	if m["tenant"] != "acme" {
		t.Errorf("tenant lost from the zero-timestamp encoding: %s", raw)
	}
}
