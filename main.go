package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/livepeer/jwt-issuer/auth"
)

func main() {
	listen := flag.String("listen", ":8082", "HTTP listen address")
	keyPath := flag.String("jwkPrivateKeyPath", "", "Path to RSA private key PEM file (required)")
	keyID := flag.String("jwkKeyID", "livepeer-key-1", "Key ID for the JWKS kid header")
	siweDomain := flag.String("siweDomain", "", "Domain for SIWE message verification (required)")
	tokenTTL := flag.Duration("tokenTTL", 8*time.Hour, "JWT token lifetime")
	allowedOrigins := flag.String("allowedOrigins", "*", "Comma-separated list of allowed CORS origins (default: * for all)")
	flag.Parse()

	if *keyPath == "" {
		log.Fatal("-jwkPrivateKeyPath is required")
	}
	if *siweDomain == "" {
		log.Fatal("-siweDomain is required")
	}

	// Load RSA private key
	privKey, err := auth.LoadPrivateKey(*keyPath)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}
	log.Printf("Loaded RSA private key from %s (%d bits)", *keyPath, privKey.N.BitLen())

	// Create the issuer
	issuer := &auth.Issuer{
		Nonces:   auth.NewNonceStore(),
		Domain:   *siweDomain,
		TokenTTL: *tokenTTL,
		KeyID:    *keyID,
		PrivKey:  privKey,
	}
	defer issuer.Nonces.Close()

	// Configure CORS
	var origins []string
	if *allowedOrigins == "*" {
		origins = []string{"*"}
	} else {
		// Split comma-separated origins
		for _, o := range splitAndTrim(*allowedOrigins, ",") {
			if o != "" {
				origins = append(origins, o)
			}
		}
	}

	corsConfig := &auth.CORSConfig{
		AllowedOrigins: origins,
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type", "Authorization", "X-Requested-With", "Accept"},
		MaxAge:         3600,
	}

	// Register routes
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/nonce", issuer.HandleNonce)
	mux.HandleFunc("POST /auth/login", issuer.HandleLogin)
	mux.HandleFunc("POST /auth/token", issuer.HandleToken)
	mux.HandleFunc("GET /.well-known/jwks.json", auth.JWKSHandler(&privKey.PublicKey, *keyID))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	// Wrap all routes with CORS middleware
	handler := auth.CORSMiddleware(corsConfig, mux)

	log.Printf("JWT Issuer starting on %s (domain=%s, keyID=%s, tokenTTL=%s)", *listen, *siweDomain, *keyID, *tokenTTL)
	log.Printf("CORS enabled: origins=%v", origins)

	srv := &http.Server{
		Addr:         *listen,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// splitAndTrim splits a string by delimiter and trims whitespace from each part
func splitAndTrim(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := []string{}
	for _, part := range splitString(s, sep) {
		trimmed := trimSpace(part)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

func splitString(s, sep string) []string {
	if sep == "" {
		return []string{s}
	}
	var result []string
	start := 0
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
