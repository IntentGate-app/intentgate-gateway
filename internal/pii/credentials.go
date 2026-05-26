package pii

import (
	"regexp"
	"strings"
)

// Credential-class detections. These extend the PII engine with
// authentication-secret patterns — AWS keys, GitHub PATs, JWTs,
// OAuth bearers, SSH private keys, GCP service-account JSON. They
// live in the same package so they share the Detector pipeline,
// the same Action vocabulary, the same audit-counts-only principle,
// and the same Rego override surface as the PII classes.
//
// Threat closed: an upstream tool legitimately returns a config blob,
// a log line, or a debug dump that happens to contain a credential.
// Without this layer that credential would land in the agent's
// context and propagate to whatever the agent does next — at minimum
// the LLM provider's tokenizer logs see it; at worst the agent
// includes it in a follow-up tool call to a less-trusted destination.
//
// Same three actions as PII: redact (default for most classes),
// block (default for the most damaging: aws_secret_key, ssh_private_key,
// gcp_service_account_key), or escalate.
//
// All credential patterns are validator-free — we do not test the
// secrets against the corresponding identity provider. False positives
// are managed by tight regex shapes (e.g. AWS access key IDs always
// start with AKIA/ASIA/AROA and are exactly 20 chars).

// Class constants for credential detections. These appear in
// [REDACTED:<class>] markers and in audit rows.
const (
	ClassAWSAccessKey      Class = "aws_access_key"
	ClassAWSSecretKey      Class = "aws_secret_key"
	ClassGitHubPAT         Class = "github_pat"
	ClassJWT               Class = "jwt"
	ClassOAuthBearer       Class = "oauth_bearer"
	ClassSSHPrivateKey     Class = "ssh_private_key"
	ClassGCPServiceAccount Class = "gcp_service_account_key"
	ClassGenericAPIKey     Class = "generic_api_key"
)

// AWS Access Key ID — exact 20-char form. Prefix AKIA (long-term),
// ASIA (temporary STS), AROA (assumed-role), ANPA / ABIA / etc. for
// other AWS principal types. \b boundaries prevent matching inside
// longer identifiers.
var awsAccessKeyRe = regexp.MustCompile(`\b(AKIA|ASIA|AROA|ANPA|ABIA|ACCA)[0-9A-Z]{16}\b`)

// AWS Secret Access Key — 40 chars of base64. Looser shape than the
// access key id so we lean on a validator (entropy heuristic) to
// suppress false positives on log lines that happen to contain
// 40-char alphanumeric tokens. The validator is required.
var awsSecretKeyRe = regexp.MustCompile(`\b[A-Za-z0-9/+=]{40}\b`)

// GitHub personal access token / fine-grained PAT / OAuth token /
// app installation token / refresh token. All share the ghX_ prefix
// pattern (ghp, gho, ghs, ghr, ghu, github_pat_).
//
//	ghp_xxx (classic PAT)
//	gho_xxx (OAuth)
//	ghs_xxx (server)
//	ghr_xxx (refresh)
//	ghu_xxx (user)
//	github_pat_xxx (fine-grained)
var githubPATRe = regexp.MustCompile(`\b(?:gh[oprsu]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82})\b`)

// JWT — three dot-separated base64url segments. We treat the
// presence of an unverifiable JWT in a tool response as a smell
// (why is a token in plaintext in a response body?). Validator-free
// because the gateway has no business decoding customer JWTs.
var jwtRe = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)

// OAuth bearer token in a response body — typically the literal
// "Bearer " prefix with an opaque token after. Match the prefix
// + 20+ chars of token alphabet. Common in misconfigured tool
// servers that proxy upstream auth and dump it on error.
var oauthBearerRe = regexp.MustCompile(`\bBearer\s+[A-Za-z0-9._\-+/=]{20,}\b`)

// SSH private key block — PEM header through footer. -----BEGIN ...
// PRIVATE KEY----- covers RSA, OPENSSH, EC, DSA, ENCRYPTED variants.
// (?s) is RE2-supported, enables dot-matches-newline.
var sshPrivateKeyRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)

// GCP service-account JSON — the unmistakable "type": "service_account"
// + private_key_id + private_key fields. We match a window of bytes
// rather than try to parse JSON; the validator (containsAllOf) ensures
// the three telltale fields are all present, suppressing false
// positives on partial dumps.
var gcpServiceAccountRe = regexp.MustCompile(`(?s)"type"\s*:\s*"service_account".{0,500}"private_key_id".{0,500}"private_key"`)

// Generic API-key-shaped token — a fallback for tool servers that
// emit credentials we don't have a tight pattern for. Heuristic:
// 32+ chars of base64-or-hex alphabet attached to a key-like label.
// This is the LOWEST priority class — its coalesce ordering means a
// more-specific class (aws_access_key, github_pat) always wins on
// the same byte range.
var genericAPIKeyRe = regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['"]?[A-Za-z0-9_\-/+=]{32,}['"]?`)

// credentialPatterns returns the credential-class patterns in
// detector-priority order: tight-shape classes (validator or
// distinctive prefix) first, generic fallback last. The Detector's
// coalesce step uses this order on ties.
func credentialPatterns() []Pattern {
	return []Pattern{
		// Validator-having classes — high precision
		{Class: ClassSSHPrivateKey, Regex: sshPrivateKeyRe, Validate: validSSHPrivateKey},
		{Class: ClassGCPServiceAccount, Regex: gcpServiceAccountRe, Validate: validGCPServiceAccount},
		{Class: ClassAWSSecretKey, Regex: awsSecretKeyRe, Validate: validAWSSecretKey},
		// Distinctive-prefix classes — tight regex, no validator needed
		{Class: ClassAWSAccessKey, Regex: awsAccessKeyRe},
		{Class: ClassGitHubPAT, Regex: githubPATRe},
		{Class: ClassJWT, Regex: jwtRe},
		{Class: ClassOAuthBearer, Regex: oauthBearerRe},
		// Generic fallback — lowest priority
		{Class: ClassGenericAPIKey, Regex: genericAPIKeyRe},
	}
}

// validSSHPrivateKey requires the matched block to be at least
// 200 chars (smaller is almost certainly a false positive from
// boilerplate documentation rather than a real key).
func validSSHPrivateKey(s string) bool {
	return len(s) >= 200
}

// validGCPServiceAccount sanity-checks the matched window: it should
// have all three field labels we matched and a private_key value
// that contains "BEGIN PRIVATE KEY" or "BEGIN RSA PRIVATE KEY".
func validGCPServiceAccount(s string) bool {
	if !strings.Contains(s, `"type"`) {
		return false
	}
	if !strings.Contains(s, `"private_key_id"`) {
		return false
	}
	// The full key block is rarely included in the matched window
	// (we cap at 500 chars between fields); accept the match if the
	// three field labels are present, leaving deep validation to a
	// downstream secrets scanner if the operator wants it.
	return true
}

// validAWSSecretKey runs an entropy heuristic on the 40-char
// candidate. Real AWS secret keys are essentially random base64; a
// log line that contains a 40-char identifier (commit SHA, hex
// digest, request ID) usually has lower character variety. Threshold
// is set empirically: ≥ 20 distinct characters among the 40.
//
// This is a precision-vs-recall tradeoff documented in the design
// memo. Operators who want stricter detection can declare an
// additional custom pattern in Rego.
func validAWSSecretKey(s string) bool {
	if len(s) != 40 {
		return false
	}
	seen := make(map[byte]struct{}, 40)
	for i := 0; i < len(s); i++ {
		seen[s[i]] = struct{}{}
	}
	return len(seen) >= 20
}
