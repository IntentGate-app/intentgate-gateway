package pii

import (
	"strings"
	"testing"
)

func TestCredentials_AWSAccessKey(t *testing.T) {
	d := NewDetector([]Class{ClassAWSAccessKey})
	cases := []struct {
		in   string
		hits int
	}{
		{"AKIAIOSFODNN7EXAMPLE in a log line", 1},   // 20 chars total
		{"key: ASIAQ3EGTXYZ12345678", 1},            // ASIA + 16 chars
		{"AROAR1234567890123XY is a role", 1},       // AROA + 16 chars
		{"AKIA short", 0},                           // truncated
		{"no keys here, just AKIAA or ASIAB", 0},    // too short
		{"prefix akia1234567890123456lowercase", 0}, // must be uppercase
	}
	for _, c := range cases {
		got := d.Detect(c.in)
		if len(got) != c.hits {
			t.Errorf("input %q: expected %d hits, got %d: %+v", c.in, c.hits, len(got), got)
		}
	}
}

func TestCredentials_AWSSecretKey(t *testing.T) {
	d := NewDetector([]Class{ClassAWSSecretKey})
	// A real-looking 40-char base64 secret (high entropy).
	realSecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	if len(realSecret) != 40 {
		t.Fatalf("test fixture wrong length: %d", len(realSecret))
	}
	hits := d.Detect("secret=" + realSecret + " end")
	if len(hits) != 1 {
		t.Errorf("expected 1 hit on real-looking secret, got %d: %+v", len(hits), hits)
	}

	// Low-entropy 40-char strings should not match (commit shas, padded
	// hashes that happen to be alphanumeric).
	noiseCases := []string{
		strings.Repeat("a", 40),                    // 1 distinct char
		strings.Repeat("ab", 20),                   // 2 distinct chars
		"0000000000000000000000000000000000000000", // 40 zeroes
	}
	for _, in := range noiseCases {
		hits := d.Detect(in)
		if len(hits) != 0 {
			t.Errorf("low-entropy input %q should not match, got %+v", in, hits)
		}
	}
}

func TestCredentials_GitHubPAT(t *testing.T) {
	d := NewDetector([]Class{ClassGitHubPAT})
	cases := []string{
		"ghp_" + strings.Repeat("A", 36),
		"gho_" + strings.Repeat("B", 36),
		"ghs_" + strings.Repeat("C", 36),
		"github_pat_" + strings.Repeat("D", 82),
	}
	for _, in := range cases {
		hits := d.Detect("token=" + in)
		if len(hits) != 1 {
			t.Errorf("%q: expected 1 hit, got %d: %+v", in, len(hits), hits)
		}
	}

	// Negatives
	negCases := []string{
		"ghp_short",
		"ghx_unknownprefix_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"github_pat_too_short",
	}
	for _, in := range negCases {
		hits := d.Detect(in)
		if len(hits) != 0 {
			t.Errorf("%q should not match, got %+v", in, hits)
		}
	}
}

func TestCredentials_JWT(t *testing.T) {
	d := NewDetector([]Class{ClassJWT})
	// Real-shaped JWT (eyJ prefix + dot-separated b64url).
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2UifQ.abc123_-XYZ"
	hits := d.Detect("Authorization: " + jwt)
	if len(hits) != 1 {
		t.Errorf("expected 1 JWT hit, got %d: %+v", len(hits), hits)
	}

	// Not a JWT — missing dots / wrong prefix.
	if got := d.Detect("not.a.jwt"); len(got) != 0 {
		t.Errorf("'not.a.jwt' should not match, got %+v", got)
	}
}

func TestCredentials_OAuthBearer(t *testing.T) {
	d := NewDetector([]Class{ClassOAuthBearer})
	hits := d.Detect("Authorization: Bearer abcdef1234567890_xyzABCDEFGHIJK")
	if len(hits) != 1 {
		t.Errorf("expected 1 bearer hit, got %d: %+v", len(hits), hits)
	}

	if got := d.Detect("Bearer short"); len(got) != 0 {
		t.Errorf("'Bearer short' should not match (too short), got %+v", got)
	}
}

func TestCredentials_SSHPrivateKey(t *testing.T) {
	d := NewDetector([]Class{ClassSSHPrivateKey})

	// Real-shape OPENSSH key (well above 200 chars).
	key := "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		strings.Repeat("AAAAB3NzaC1yc2EAAAADAQABAAABAQ", 8) + "\n" +
		"-----END OPENSSH PRIVATE KEY-----"
	hits := d.Detect("key:\n" + key + "\nend")
	if len(hits) != 1 {
		t.Errorf("expected 1 SSH key hit, got %d", len(hits))
	}

	// Short banner only — under the 200-char validator threshold.
	short := "-----BEGIN PRIVATE KEY-----\nshort\n-----END PRIVATE KEY-----"
	if got := d.Detect(short); len(got) != 0 {
		t.Errorf("short SSH banner should not match (below 200-char threshold), got %+v", got)
	}
}

func TestCredentials_GCPServiceAccount(t *testing.T) {
	d := NewDetector([]Class{ClassGCPServiceAccount})
	blob := `{
		"type": "service_account",
		"project_id": "my-project",
		"private_key_id": "abc123",
		"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANB..."
	}`
	hits := d.Detect("config: " + blob)
	if len(hits) != 1 {
		t.Errorf("expected 1 GCP SA hit, got %d: %+v", len(hits), hits)
	}

	// No private_key_id → validator rejects.
	partial := `{"type":"service_account","project_id":"x","private_key":"y"}`
	if got := d.Detect(partial); len(got) != 0 {
		t.Errorf("partial SA (no private_key_id) should not match, got %+v", got)
	}
}

func TestCredentials_GenericAPIKey(t *testing.T) {
	d := NewDetector([]Class{ClassGenericAPIKey})
	cases := []string{
		"api_key=abcdef1234567890abcdef1234567890ab",
		`API_KEY: "abcdef1234567890abcdef1234567890ab"`,
		"secret = 'abcdef1234567890abcdef1234567890ab'",
		"password: abcdef1234567890abcdef1234567890ab",
	}
	for _, in := range cases {
		hits := d.Detect(in)
		if len(hits) != 1 {
			t.Errorf("%q: expected 1 hit, got %d: %+v", in, len(hits), hits)
		}
	}

	// Too short — fewer than 32 chars after the label.
	if got := d.Detect("api_key=short"); len(got) != 0 {
		t.Errorf("short api_key should not match, got %+v", got)
	}
}

func TestCredentials_RealisticConfigDump(t *testing.T) {
	// A response that dumps several credentials at once. Verify all
	// classes are detected and Redact strips every secret cleanly.
	dump := `
config:
  aws_access_key_id: AKIAIOSFODNN7EXAMPLE
  aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  github_pat: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  jwt: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2UifQ.abc123_-XYZ
`
	d := NewDetector(nil) // all built-ins
	matches := d.Detect(dump)

	gotClasses := make(map[Class]bool)
	for _, m := range matches {
		gotClasses[m.Class] = true
	}
	wantClasses := []Class{ClassAWSAccessKey, ClassAWSSecretKey, ClassGitHubPAT, ClassJWT}
	for _, c := range wantClasses {
		if !gotClasses[c] {
			t.Errorf("expected at least one match for class %s in realistic dump, got none", c)
		}
	}

	out, _ := Redact(dump, matches)
	leaks := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"eyJhbGciOiJIUzI1NiJ9",
	}
	for _, leak := range leaks {
		if strings.Contains(out, leak) {
			t.Errorf("leak after redaction: %q remained in output", leak)
		}
	}
}
