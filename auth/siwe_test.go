package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt/v5"
	siwe "github.com/spruceid/siwe-go"
)

func testIssuer(t *testing.T) *Issuer {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return &Issuer{
		Nonces:   NewNonceStore(),
		Domain:   "localhost",
		TokenTTL: 1 * time.Hour,
		KeyID:    "test-key-1",
		PrivKey:  privKey,
	}
}

// --- Nonce Tests ---

func TestNonceStore_GenerateAndConsume(t *testing.T) {
	ns := NewNonceStore()
	defer ns.Close()

	nonce, err := ns.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(nonce) != NonceBytes*2 {
		t.Fatalf("expected nonce length %d, got %d", NonceBytes*2, len(nonce))
	}

	if !ns.Consume(nonce) {
		t.Fatal("first consume should succeed")
	}
	if ns.Consume(nonce) {
		t.Fatal("second consume should fail")
	}
}

func TestNonceStore_ConsumeUnknown(t *testing.T) {
	ns := NewNonceStore()
	defer ns.Close()

	if ns.Consume("nonexistent") {
		t.Fatal("unknown nonce should not be consumed")
	}
}

func TestNonceStore_Expired(t *testing.T) {
	ns := NewNonceStore()
	defer ns.Close()

	ns.mu.Lock()
	ns.nonces["old"] = nonceEntry{createdAt: time.Now().Add(-10 * time.Minute)}
	ns.mu.Unlock()

	if ns.Consume("old") {
		t.Fatal("expired nonce should not be consumed")
	}
}

func TestNonceStore_MaxPending(t *testing.T) {
	ns := &NonceStore{
		nonces:  make(map[string]nonceEntry),
		closeCh: make(chan struct{}),
	}
	defer ns.Close()

	for i := 0; i < NonceMaxPending; i++ {
		if _, err := ns.Generate(); err != nil {
			t.Fatalf("generate %d: %v", i, err)
		}
	}
	if _, err := ns.Generate(); err == nil {
		t.Fatal("should fail when max pending reached")
	}
}

// --- JWT Issuance Tests ---

func TestIssueToken_RS256(t *testing.T) {
	iss := testIssuer(t)
	defer iss.Nonces.Close()

	tokenStr, expiresAt, err := iss.IssueToken("0xAbCdEf0123456789AbCdEf0123456789AbCdEf01")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("empty token")
	}
	if expiresAt.Before(time.Now()) {
		t.Fatal("token already expired")
	}

	// Parse and verify with the public key
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %v", token.Header["alg"])
		}
		if token.Header["kid"] != "test-key-1" {
			return nil, fmt.Errorf("unexpected kid: %v", token.Header["kid"])
		}
		return &iss.PrivKey.PublicKey, nil
	}, jwt.WithAudience(ExpectedAudience))

	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !token.Valid {
		t.Fatal("token not valid")
	}
	if claims.Subject != "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01" {
		t.Fatalf("unexpected sub: %s", claims.Subject)
	}
	if claims.Issuer != "livepeer-jwt-issuer" {
		t.Fatalf("unexpected iss: %s", claims.Issuer)
	}
	if claims.Scope != "sign:orchestrator sign:payment sign:byoc" {
		t.Fatalf("unexpected scope: %s", claims.Scope)
	}
}

// --- HandleNonce Tests ---

func TestHandleNonce(t *testing.T) {
	iss := testIssuer(t)
	defer iss.Nonces.Close()

	req := httptest.NewRequest("POST", "/auth/nonce", nil)
	rec := httptest.NewRecorder()
	iss.HandleNonce(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}

	var resp NonceResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Nonce == "" {
		t.Fatal("empty nonce")
	}
	if resp.Domain != "localhost" {
		t.Fatalf("unexpected domain: %s", resp.Domain)
	}
}

// --- HandleLogin Tests ---

func TestHandleLogin_MissingFields(t *testing.T) {
	iss := testIssuer(t)
	defer iss.Nonces.Close()

	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	iss.HandleLogin(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandleLogin_InvalidSIWE(t *testing.T) {
	iss := testIssuer(t)
	defer iss.Nonces.Close()

	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"message":"garbage","signature":"0x1234"}`))
	rec := httptest.NewRecorder()
	iss.HandleLogin(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandleLogin_DomainMismatch(t *testing.T) {
	iss := testIssuer(t)
	defer iss.Nonces.Close()

	userKey, _ := crypto.GenerateKey()
	userAddr := crypto.PubkeyToAddress(userKey.PublicKey)

	nonce, _ := iss.Nonces.Generate()

	now := time.Now().UTC()
	msg, _ := siwe.InitMessage(
		"wrong-domain.com",
		userAddr.Hex(),
		"https://wrong-domain.com",
		nonce,
		map[string]interface{}{
			"issuedAt": now.Format(time.RFC3339),
		},
	)

	msgStr := msg.String()
	hash := accounts.TextHash([]byte(msgStr))
	sig, _ := crypto.Sign(hash, userKey)
	if sig[64] < 27 {
		sig[64] += 27
	}

	body := fmt.Sprintf(`{"message":%q,"signature":"0x%x"}`, msgStr, sig)
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	iss.HandleLogin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleLogin_NonceReuse(t *testing.T) {
	iss := testIssuer(t)
	defer iss.Nonces.Close()

	userKey, _ := crypto.GenerateKey()
	userAddr := crypto.PubkeyToAddress(userKey.PublicKey)

	nonce, _ := iss.Nonces.Generate()

	now := time.Now().UTC()
	msg, _ := siwe.InitMessage(
		"localhost",
		userAddr.Hex(),
		"https://localhost",
		nonce,
		map[string]interface{}{
			"issuedAt":       now.Format(time.RFC3339),
			"expirationTime": now.Add(5 * time.Minute).Format(time.RFC3339),
		},
	)

	msgStr := msg.String()
	hash := accounts.TextHash([]byte(msgStr))
	sig, _ := crypto.Sign(hash, userKey)
	if sig[64] < 27 {
		sig[64] += 27
	}
	body := fmt.Sprintf(`{"message":%q,"signature":"0x%x"}`, msgStr, sig)

	// First login succeeds
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	iss.HandleLogin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first login: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Second login with same nonce fails
	req = httptest.NewRequest("POST", "/auth/login", strings.NewReader(body))
	rec = httptest.NewRecorder()
	iss.HandleLogin(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("second login: expected 401, got %d", rec.Code)
	}
}

// --- Full Flow Test ---

func TestFullFlow_SIWE_Login_And_JWT_Verify(t *testing.T) {
	iss := testIssuer(t)
	defer iss.Nonces.Close()

	userKey, _ := crypto.GenerateKey()
	userAddr := crypto.PubkeyToAddress(userKey.PublicKey)

	// Step 1: Get nonce
	nonceReq := httptest.NewRequest("POST", "/auth/nonce", nil)
	nonceRec := httptest.NewRecorder()
	iss.HandleNonce(nonceRec, nonceReq)
	if nonceRec.Code != http.StatusOK {
		t.Fatalf("nonce: %d", nonceRec.Code)
	}
	var nonceResp NonceResponse
	json.NewDecoder(nonceRec.Body).Decode(&nonceResp)

	// Step 2: Sign SIWE message
	now := time.Now().UTC()
	msg, err := siwe.InitMessage(
		"localhost",
		userAddr.Hex(),
		"https://localhost",
		nonceResp.Nonce,
		map[string]interface{}{
			"statement":      "Sign in to Livepeer Remote Signer Service",
			"issuedAt":       now.Format(time.RFC3339),
			"expirationTime": now.Add(5 * time.Minute).Format(time.RFC3339),
		},
	)
	if err != nil {
		t.Fatalf("init SIWE message: %v", err)
	}

	msgStr := msg.String()
	hash := accounts.TextHash([]byte(msgStr))
	sig, _ := crypto.Sign(hash, userKey)
	if sig[64] < 27 {
		sig[64] += 27
	}

	// Step 3: Login
	loginBody := fmt.Sprintf(`{"message":%q,"signature":"0x%x"}`, msgStr, sig)
	loginReq := httptest.NewRequest("POST", "/auth/login", strings.NewReader(loginBody))
	loginRec := httptest.NewRecorder()
	iss.HandleLogin(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login: %d: %s", loginRec.Code, loginRec.Body.String())
	}

	var loginResp LoginResponse
	json.NewDecoder(loginRec.Body).Decode(&loginResp)
	if loginResp.Token == "" {
		t.Fatal("empty token")
	}
	if loginResp.Address != userAddr.Hex() {
		t.Fatalf("address mismatch: got=%s want=%s", loginResp.Address, userAddr.Hex())
	}

	// Step 4: Verify the JWT with the public key (simulating what the remote signer does)
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(loginResp.Token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %v", token.Header["alg"])
		}
		return &iss.PrivKey.PublicKey, nil
	}, jwt.WithAudience(ExpectedAudience))
	if err != nil {
		t.Fatalf("JWT verify: %v", err)
	}
	if !token.Valid {
		t.Fatal("JWT not valid")
	}
	if claims.Subject != userAddr.Hex() {
		t.Fatalf("JWT sub: got=%s want=%s", claims.Subject, userAddr.Hex())
	}
}

// --- JWKS Handler Tests ---

func TestJWKSHandler(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	handler := JWKSHandler(&privKey.PublicKey, "test-key-1")

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type: %s", ct)
	}

	var jwks JWKSet
	if err := json.NewDecoder(rec.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	key := jwks.Keys[0]
	if key.Kty != "RSA" {
		t.Fatalf("kty: %s", key.Kty)
	}
	if key.Kid != "test-key-1" {
		t.Fatalf("kid: %s", key.Kid)
	}
	if key.Alg != "RS256" {
		t.Fatalf("alg: %s", key.Alg)
	}
	if key.N == "" || key.E == "" {
		t.Fatal("missing n or e")
	}
}
