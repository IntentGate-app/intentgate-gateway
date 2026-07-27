// Package bundle ingests, verifies, and hot-swaps compiled IntentGrant policy
// bundles for the IntentGate runtime.
//
// A CompiledGateBundle is the output of the IntentGrant Policy Compiler
// (console-pro/lib/intentgrant/compile.ts). This file mirrors that contract on
// the Go side so a bundle produced by the control plane deserialises 1:1 here.
// The registry (loader.go) holds the active ruleset per subject in memory; the
// evaluator (evaluator.go) runs the dual path against it.
package bundle

import "time"

// CompiledGateBundle is one signed, versioned artifact with two execution
// targets: StaticCapabilities (token caveats, evaluated locally) and
// RuntimeGuardRules (payload-inspection hooks). AttestationConfig drives Proof.
type CompiledGateBundle struct {
	BundleID           string             `json:"bundle_id"`
	GrantID            string             `json:"grant_id"`
	Version            string             `json:"version"`
	CompiledAt         time.Time          `json:"compiled_at"`
	Signature          []byte             `json:"signature"` // Ed25519 over the canonical bundle
	StaticCapabilities StaticCapabilities `json:"static_capabilities"`
	RuntimeGuardRules  RuntimeGuardRules  `json:"runtime_guard_rules"`
	AttestationConfig  AttestationConfig  `json:"attestation_config"`
}

type StaticCapabilities struct {
	Subject       string  `json:"subject"`        // SPIFFE id / agent id; becomes Token.Subject
	DelegatedFrom string  `json:"delegated_from"` // provenance: the human owner
	Caveats       Caveats `json:"caveats"`
}

// Caveats mirror the v4 macaroon caveat vocabulary. Zero values mean "unset".
type Caveats struct {
	AllowedTools          []string  `json:"allowed_tools"`
	AllowedMcpServers     []string  `json:"allowed_mcp_servers,omitempty"`
	Zone                  string    `json:"zone,omitempty"`
	ValidUntil            time.Time `json:"valid_until,omitempty"` // zero = no expiry
	MaxExecutionCostCents int64     `json:"max_execution_cost_cents,omitempty"`
	RateLimitPerMin       int       `json:"rate_limit_per_min,omitempty"`
	MaxCalls              int       `json:"max_calls,omitempty"`
	MaxRiskScore          int       `json:"max_risk_score,omitempty"`
	ObserveOnly           bool      `json:"observe_only"` // monitor gateMode
}

type RuntimeGuardRules struct {
	ActionGuard           *ActionGuardHook `json:"actionguard,omitempty"`
	ReferenceVerification *RefVerification `json:"reference_verification,omitempty"`
}

type ActionGuardHook struct {
	InspectPayload      bool           `json:"inspect_payload"`
	IrreversibleActions []string       `json:"irreversible_actions"`
	MagnitudeCheck      MagnitudeCheck `json:"magnitude_check"`
}

type MagnitudeCheck struct {
	Enabled    bool   `json:"enabled"`
	MaxCents   int64  `json:"max_cents"`
	OnExceeded string `json:"on_exceeded"` // "escalate_to_human"
}

type RefVerification struct {
	VendorMaster VendorMaster `json:"vendor_master"`
}

type VendorMaster struct {
	Enabled   bool   `json:"enabled"`
	CheckType string `json:"check_type"` // "quarantine_if_unlisted"
}

type AttestationConfig struct {
	EmitProof   bool   `json:"emit_proof"`
	ProofDomain string `json:"proof_domain"` // "Proof"
}
