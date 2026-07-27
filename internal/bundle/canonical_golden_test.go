package bundle

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"
)

// Golden vector emitted by console-pro/lib/intentgrant/signer.check.ts. It pins
// the cross-language canonicalization contract: Go's Canonical() must produce
// these exact bytes, and the TS-produced Ed25519 signature must verify against
// them. If this test fails, the compiler and gateway have drifted and no bundle
// will load.
const goldenCanonical = `{"attestation":{"emit_proof":true,"proof_domain":"Proof"},"bundle_id":"bundle_grant-procurement-001_2026-07-27","caveats":{"allowed_mcp_servers":["ali-oss","ali-pay","ali-rds"],"allowed_tools":["oss_read","rds_query","transfer_funds"],"max_calls":5000,"max_execution_cost_cents":500,"max_risk_score":70,"observe_only":false,"rate_limit_per_min":120,"valid_until":"2026-12-31T23:59:59Z","zone":"cn-shanghai"},"compiled_at":"2026-07-27T18:25:00Z","delegated_from":"usr_jane_doe_882","grant_id":"grant-procurement-001","runtime_guard":{"actionguard":{"enabled":true,"inspect_payload":true,"irreversible_actions":["ali.transfer_funds"],"max_cents":5000000,"on_exceeded":"escalate_to_human"},"vendor_master":{"check_type":"quarantine_if_unlisted","enabled":true}},"subject":"spiffe://cluster.local/ns/prod/sa/procure-bot","version":"1.0.0"}`

const goldenPubKeyB64 = "MCowBQYDK2VwAyEAW6xLXC2htD5dhNXgYgv8HmjtKzIQQiWL55Pt9GdR85A="
const goldenSigB64 = "YnmmWqcSWmeqUoVYk+lkJqDkMovohb8X6lNUipvYhBeKbFJn1pB9Sjmm9VshLO5mmw1G+UOOZ+DdUjpwmv0dAg=="

func exampleBundle() *CompiledGateBundle {
	return &CompiledGateBundle{
		BundleID:   "bundle_grant-procurement-001_2026-07-27",
		GrantID:    "grant-procurement-001",
		Version:    "1.0.0",
		CompiledAt: time.Date(2026, 7, 27, 18, 25, 0, 0, time.UTC),
		StaticCapabilities: StaticCapabilities{
			Subject:       "spiffe://cluster.local/ns/prod/sa/procure-bot",
			DelegatedFrom: "usr_jane_doe_882",
			Caveats: Caveats{
				AllowedTools:          []string{"oss_read", "rds_query", "transfer_funds"},
				AllowedMcpServers:     []string{"ali-oss", "ali-rds", "ali-pay"},
				Zone:                  "cn-shanghai",
				ValidUntil:            time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
				MaxExecutionCostCents: 500,
				RateLimitPerMin:       120,
				MaxCalls:              5000,
				MaxRiskScore:          70,
				ObserveOnly:           false,
			},
		},
		RuntimeGuardRules: RuntimeGuardRules{
			ActionGuard: &ActionGuardHook{
				InspectPayload:      true,
				IrreversibleActions: []string{"ali.transfer_funds"},
				MagnitudeCheck:      MagnitudeCheck{Enabled: true, MaxCents: 5000000, OnExceeded: "escalate_to_human"},
			},
			ReferenceVerification: &RefVerification{
				VendorMaster: VendorMaster{Enabled: true, CheckType: "quarantine_if_unlisted"},
			},
		},
		AttestationConfig: AttestationConfig{EmitProof: true, ProofDomain: "Proof"},
	}
}

func TestCanonicalMatchesGolden(t *testing.T) {
	got := string(Canonical(exampleBundle()))
	if got != goldenCanonical {
		t.Fatalf("canonical bytes drifted from the TS signer.\n got: %s\nwant: %s", got, goldenCanonical)
	}
}

func TestGoldenSignatureVerifies(t *testing.T) {
	der, err := base64.StdEncoding.DecodeString(goldenPubKeyB64)
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("parse pubkey: %v", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("not an ed25519 public key: %T", pub)
	}
	sig, err := base64.StdEncoding.DecodeString(goldenSigB64)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	b := exampleBundle()
	b.Signature = sig
	if !ed25519.Verify(edPub, Canonical(b), sig) {
		t.Fatal("TS-produced signature did not verify against Go Canonical(); the seam is broken")
	}
}
