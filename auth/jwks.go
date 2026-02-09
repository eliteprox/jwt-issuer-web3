package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// JWK represents a single JSON Web Key (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSet represents a JSON Web Key Set (RFC 7517).
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// rsaPublicKeyToJWK converts an RSA public key to a JWK with the given key ID.
func rsaPublicKeyToJWK(pub *rsa.PublicKey, keyID string) JWK {
	return JWK{
		Kty: "RSA",
		Kid: keyID,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(bigIntToBytes(pub.E)),
	}
}

// bigIntToBytes converts an int (the RSA exponent) to big-endian bytes.
func bigIntToBytes(e int) []byte {
	// RSA public exponent is typically 65537 (3 bytes)
	if e == 0 {
		return []byte{0}
	}
	var result []byte
	for e > 0 {
		result = append([]byte{byte(e & 0xff)}, result...)
		e >>= 8
	}
	return result
}

// JWKSHandler returns an http.HandlerFunc that serves the JWKS endpoint.
func JWKSHandler(publicKey *rsa.PublicKey, keyID string) http.HandlerFunc {
	// Pre-compute the JWKS response since it doesn't change.
	jwkSet := JWKSet{
		Keys: []JWK{rsaPublicKeyToJWK(publicKey, keyID)},
	}
	jwksBytes, _ := json.Marshal(jwkSet)

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(jwksBytes)
	}
}
