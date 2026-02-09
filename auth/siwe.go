package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	siwe "github.com/spruceid/siwe-go"
)

// Issuer holds the state for SIWE authentication and JWT issuance.
type Issuer struct {
	Nonces    *NonceStore
	Domain    string
	TokenTTL  time.Duration
	KeyID     string
	PrivKey   *rsa.PrivateKey
}

// LoadPrivateKey reads an RSA private key from a PEM file.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	// Try PKCS#1 first, then PKCS#8
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsed, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse private key (PKCS1: %v, PKCS8: %v)", err, err2)
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
		key = rsaKey
	}

	if key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA key must be at least 2048 bits (got %d)", key.N.BitLen())
	}

	return key, nil
}

// MaxTokenTTL is the maximum allowed token lifetime (30 days).
var MaxTokenTTL = 30 * 24 * time.Hour

// IssueToken creates and signs a JWT for the given user ETH address using RS256.
func (iss *Issuer) IssueToken(sub string) (string, time.Time, error) {
	return iss.IssueTokenWithTTL(sub, iss.TokenTTL, "", "")
}

// IssueTokenWithTTL creates a JWT with a custom TTL, name, and scope.
func (iss *Issuer) IssueTokenWithTTL(sub string, ttl time.Duration, name string, scope string) (string, time.Time, error) {
	// Clamp TTL to server maximum
	if ttl <= 0 {
		ttl = iss.TokenTTL
	}
	if ttl > MaxTokenTTL {
		ttl = MaxTokenTTL
	}

	if scope == "" {
		scope = "sign:orchestrator sign:payment sign:byoc"
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Issuer:    "livepeer-jwt-issuer",
			Audience:  jwt.ClaimStrings{ExpectedAudience},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
		Scope: scope,
		Tier:  "standard",
		Name:  name,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = iss.KeyID

	signed, err := token.SignedString(iss.PrivKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign JWT: %w", err)
	}
	return signed, expiresAt, nil
}

// --- HTTP Handlers ---

// NonceRequest is empty (POST with no body).
// NonceResponse is the response for POST /auth/nonce.
type NonceResponse struct {
	Nonce  string `json:"nonce"`
	Domain string `json:"domain"`
}

// HandleNonce handles POST /auth/nonce -- returns a fresh nonce for SIWE login.
func (iss *Issuer) HandleNonce(w http.ResponseWriter, r *http.Request) {
	nonce, err := iss.Nonces.Generate()
	if err != nil {
		log.Printf("WARN: Failed to generate nonce: %v", err)
		http.Error(w, `{"error":"failed to generate nonce"}`, http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(NonceResponse{
		Nonce:  nonce,
		Domain: iss.Domain,
	})
}

// LoginRequest is the expected request body for POST /auth/login.
type LoginRequest struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

// LoginResponse is the response body for a successful login.
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	Address   string `json:"address"`
}

// TokenRequest is the body for POST /auth/token.
type TokenRequest struct {
	Name  string `json:"name"`
	TTL   string `json:"ttl"`
	Scope string `json:"scope"`
}

// TokenResponse is the response for POST /auth/token.
type TokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	Address   string `json:"address"`
	Name      string `json:"name"`
	Scope     string `json:"scope"`
	TTL       string `json:"ttl"`
}

// HandleToken handles POST /auth/token -- issues a new JWT for an already-authenticated user.
// Requires Authorization: Bearer <valid-jwt> header.
func (iss *Issuer) HandleToken(w http.ResponseWriter, r *http.Request) {
	// Extract and validate the existing JWT from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
		http.Error(w, `{"error":"missing or invalid Authorization header"}`, http.StatusUnauthorized)
		return
	}
	tokenString := authHeader[7:]

	// Parse and validate the existing JWT
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return &iss.PrivKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		log.Printf("WARN: Token validation failed: %v", err)
		http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
		return
	}

	existingClaims, ok := token.Claims.(*Claims)
	if !ok || existingClaims.Subject == "" {
		http.Error(w, `{"error":"invalid token claims"}`, http.StatusUnauthorized)
		return
	}

	// Parse the request body
	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Parse requested TTL
	ttl := iss.TokenTTL
	if req.TTL != "" {
		parsed, err := time.ParseDuration(req.TTL)
		if err != nil {
			http.Error(w, `{"error":"invalid TTL format (use Go duration like 1h, 24h, 168h)"}`, http.StatusBadRequest)
			return
		}
		ttl = parsed
	}

	// Determine scope
	scope := req.Scope
	if scope == "" {
		scope = existingClaims.Scope
	}

	// Issue a new token
	newToken, expiresAt, err := iss.IssueTokenWithTTL(existingClaims.Subject, ttl, req.Name, scope)
	if err != nil {
		log.Printf("ERROR: Failed to issue token: %v", err)
		http.Error(w, `{"error":"failed to issue token"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("INFO: Token issued for %s (name=%q, ttl=%s)", existingClaims.Subject, req.Name, ttl)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenResponse{
		Token:     newToken,
		ExpiresAt: expiresAt.Format(time.RFC3339),
		Address:   existingClaims.Subject,
		Name:      req.Name,
		Scope:     scope,
		TTL:       ttl.String(),
	})
}

// HandleLogin handles POST /auth/login -- verifies a SIWE signature and issues a JWT.
func (iss *Issuer) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Message == "" || req.Signature == "" {
		http.Error(w, `{"error":"message and signature are required"}`, http.StatusBadRequest)
		return
	}

	// Parse the SIWE message (EIP-4361)
	msg, err := siwe.ParseMessage(req.Message)
	if err != nil {
		log.Printf("WARN: SIWE parse failed: %v", err)
		http.Error(w, `{"error":"invalid SIWE message format"}`, http.StatusBadRequest)
		return
	}

	// Validate domain
	if msg.GetDomain() != iss.Domain {
		log.Printf("WARN: SIWE domain mismatch: got=%s want=%s", msg.GetDomain(), iss.Domain)
		http.Error(w, `{"error":"domain mismatch"}`, http.StatusBadRequest)
		return
	}

	// Consume the nonce (must be valid and unused)
	if !iss.Nonces.Consume(msg.GetNonce()) {
		http.Error(w, `{"error":"invalid or expired nonce"}`, http.StatusUnauthorized)
		return
	}

	// Verify the EIP-191 signature -- recovers signer address and checks it matches
	_, err = msg.VerifyEIP191(req.Signature)
	if err != nil {
		log.Printf("WARN: SIWE signature verification failed: %v", err)
		http.Error(w, `{"error":"signature verification failed"}`, http.StatusUnauthorized)
		return
	}

	// The address from the parsed message is the authenticated user
	userAddr := msg.GetAddress().Hex()

	// Issue a JWT signed with RS256
	token, expiresAt, err := iss.IssueToken(userAddr)
	if err != nil {
		log.Printf("ERROR: Failed to issue JWT: %v", err)
		http.Error(w, `{"error":"failed to issue token"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("INFO: SIWE login successful for %s", userAddr)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt.Format(time.RFC3339),
		Address:   userAddr,
	})
}
