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

	// Register routes
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/nonce", issuer.HandleNonce)
	mux.HandleFunc("POST /auth/login", issuer.HandleLogin)
	mux.HandleFunc("GET /.well-known/jwks.json", auth.JWKSHandler(&privKey.PublicKey, *keyID))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	log.Printf("JWT Issuer starting on %s (domain=%s, keyID=%s, tokenTTL=%s)", *listen, *siweDomain, *keyID, *tokenTTL)

	srv := &http.Server{
		Addr:         *listen,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
