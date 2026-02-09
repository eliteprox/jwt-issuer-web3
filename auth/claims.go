package auth

import "github.com/golang-jwt/jwt/v5"

// ExpectedAudience is the required JWT audience claim that the remote signer validates.
const ExpectedAudience = "livepeer-remote-signer"

// Claims represents the JWT claims issued after a successful SIWE login.
type Claims struct {
	jwt.RegisteredClaims

	// Scope defines allowed operations, e.g. "sign:orchestrator sign:payment sign:byoc"
	Scope string `json:"scope,omitempty"`

	// SpendingCapWei is the per-session spending limit in wei (informational)
	SpendingCapWei string `json:"spending_cap_wei,omitempty"`

	// Tier is the user's service tier, e.g. "standard", "premium"
	Tier string `json:"tier,omitempty"`
}
