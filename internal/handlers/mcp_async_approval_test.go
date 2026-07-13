package handlers

import (
	"testing"

	"github.com/IntentGate-app/intentgate-gateway/internal/approvals"
	"github.com/IntentGate-app/intentgate-gateway/internal/mcp"
)

// TestSameApprovalCall covers the replay guard for async-hold resume: an
// approval is bound to the exact call that was escalated, so it cannot be
// reused for a different agent, tenant, tool, or arguments.
func TestSameApprovalCall(t *testing.T) {
	row := approvals.PendingRequest{
		AgentID: "agent-a",
		Tenant:  "acme",
		Tool:    "pay",
		Args:    map[string]any{"amount": 1000, "payee": "vendor-1"},
	}
	base := &mcp.ToolCallParams{
		Name:      "pay",
		Arguments: map[string]any{"amount": 1000, "payee": "vendor-1"},
	}

	if !sameApprovalCall(row, "agent-a", "acme", base) {
		t.Fatal("identical call should match the approval")
	}
	if sameApprovalCall(row, "agent-b", "acme", base) {
		t.Fatal("a different agent must not reuse the approval")
	}
	if sameApprovalCall(row, "agent-a", "other-tenant", base) {
		t.Fatal("a different tenant must not reuse the approval")
	}
	if sameApprovalCall(row, "agent-a", "acme",
		&mcp.ToolCallParams{Name: "refund", Arguments: base.Arguments}) {
		t.Fatal("a different tool must not reuse the approval")
	}
	if sameApprovalCall(row, "agent-a", "acme",
		&mcp.ToolCallParams{Name: "pay", Arguments: map[string]any{"amount": 9999, "payee": "vendor-1"}}) {
		t.Fatal("changed arguments must not reuse the approval (replay prevention)")
	}
	// Same arguments supplied in a different construction order must still
	// match: encoding/json sorts map keys, so the fingerprint is stable.
	if !sameApprovalCall(row, "agent-a", "acme",
		&mcp.ToolCallParams{Name: "pay", Arguments: map[string]any{"payee": "vendor-1", "amount": 1000}}) {
		t.Fatal("identical arguments should match regardless of map ordering")
	}
}
