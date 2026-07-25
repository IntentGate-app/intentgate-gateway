// Package obo implements lab-first On-Behalf-Of (OBO) tokens.
//
// An OBO token carries the DELEGATING PRINCIPAL — the human a call is being
// made on behalf of — alongside that human's governance attributes (role,
// department, delegated spend limit, MFA state). It lets the gateway enforce
// the user->agent authorization layer (Layer 2 of the composition model)
// without the gateway itself talking to an identity provider.
//
// The agent forwards this token on the call (e.g. in an X-IntentGate-OBO
// header). The gateway verifies the HMAC signature with a shared key, checks
// expiry, and surfaces the delegating principal + attributes into the policy
// decision input so Rego rules can gate on them:
//
//	input.user.subject       -> "alice@acme"
//	input.user.attrs.role    -> "junior_accountant"
//	input.user.attrs.spend   -> "5000"
//	input.user.attrs.mfa     -> "true"
//
// This is deliberately a lab-first shape: a compact, self-contained,
// HMAC-signed token that anything (the lab generator, a demo script, the Pro
// console) can mint with the shared key. It upgrades to a real RFC 8693
// token-exchange against Entra ID or Okta later WITHOUT changing any authored
// policy — the gateway would simply verify a JWT from the IdP's JWKS instead
// of this HMAC token, and populate the same input.user shape. Policies keep
// reading input.user.attrs.* either way.
//
// Wire format (compact, URL-safe, no external deps):
//
//	base64url(JSON payload) + "." + base64url(HMAC-SHA256(payloadBytes))
//
// The payload is signed, not encrypted — attributes are authorization claims,
// not secrets. Do not put secrets in OBO attributes.
package obo

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// payload is the signed body of an OBO token.
type payload struct {
	// Subject is the agent the token was issued to (the NON-human principal
	// making the call). It should match the capability token's subject.
	Subject string `json:"sub"`
	// OnBehalfOf is the human principal the agent is acting for — the
	// delegating principal. Empty means "no delegating user" (a purely
	// autonomous agent call), in which case the user-access layer does not
	// apply and only the agent's own capability governs.
	OnBehalfOf string `json:"act"`
	// Attrs are the delegating user's governance attributes, as authored
	// upstream (IGA / IdP). Kept as strings so Rego can compare them without
	// the gateway needing to know their types.
	Attrs map[string]string `json:"attrs,omitempty"`
	// IssuedAt / Expiry are unix seconds. Expiry is required and enforced.
	IssuedAt int64 `json:"iat"`
	Expiry   int64 `json:"exp"`
}

// Principal is the verified result of an OBO token.
type Principal struct {
	Subject    string
	OnBehalfOf string
	Attrs      map[string]string
}

// Delegated reports whether a human principal is present. When false the call
// is autonomous and the user-access layer must be skipped (not failed).
func (p *Principal) Delegated() bool { return p != nil && p.OnBehalfOf != "" }

// Attr returns an attribute value (empty string if absent).
func (p *Principal) Attr(key string) string {
	if p == nil {
		return ""
	}
	return p.Attrs[key]
}

// Mint creates a signed OBO token. ttl <= 0 defaults to 5 minutes — OBO tokens
// are meant to be short-lived, minted per session/call, not long-lived grants.
func Mint(key []byte, subject, onBehalfOf string, attrs map[string]string, ttl time.Duration) (string, error) {
	if len(key) == 0 {
		return "", errors.New("obo: signing key is empty")
	}
	if subject == "" {
		return "", errors.New("obo: subject is required")
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now().UTC()
	body, err := json.Marshal(payload{
		Subject:    subject,
		OnBehalfOf: onBehalfOf,
		Attrs:      attrs,
		IssuedAt:   now.Unix(),
		Expiry:     now.Add(ttl).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("obo: marshal: %w", err)
	}
	p := base64.RawURLEncoding.EncodeToString(body)
	sig := base64.RawURLEncoding.EncodeToString(sign(key, body))
	return p + "." + sig, nil
}

// Verify checks the signature and expiry of an OBO token and returns the
// delegating principal. A malformed, tampered, or expired token is an error;
// callers MUST fail closed (treat a present-but-invalid OBO header as a denied
// request, never as "no user").
func Verify(key []byte, token string) (*Principal, error) {
	if len(key) == 0 {
		return nil, errors.New("obo: signing key is empty")
	}
	dot := strings.IndexByte(token, '.')
	if dot <= 0 || dot == len(token)-1 {
		return nil, errors.New("obo: malformed token (want payload.sig)")
	}
	body, err := base64.RawURLEncoding.DecodeString(token[:dot])
	if err != nil {
		return nil, errors.New("obo: invalid payload encoding")
	}
	gotSig, err := base64.RawURLEncoding.DecodeString(token[dot+1:])
	if err != nil {
		return nil, errors.New("obo: invalid signature encoding")
	}
	wantSig := sign(key, body)
	if subtle.ConstantTimeCompare(gotSig, wantSig) != 1 {
		return nil, errors.New("obo: signature mismatch")
	}

	var pl payload
	if err := json.Unmarshal(body, &pl); err != nil {
		return nil, fmt.Errorf("obo: unmarshal: %w", err)
	}
	if pl.Subject == "" {
		return nil, errors.New("obo: token missing subject")
	}
	if pl.Expiry == 0 {
		return nil, errors.New("obo: token missing expiry")
	}
	if time.Now().UTC().Unix() >= pl.Expiry {
		return nil, errors.New("obo: token expired")
	}
	return &Principal{Subject: pl.Subject, OnBehalfOf: pl.OnBehalfOf, Attrs: pl.Attrs}, nil
}

func sign(key, body []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(body)
	return m.Sum(nil)
}
