package auth

import (
	"fmt"
	"net/http"
	"strings"
)

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	MaxAge         int
}

// DefaultCORSConfig returns a permissive CORS configuration for development
func DefaultCORSConfig() *CORSConfig {
	return &CORSConfig{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{
			"Content-Type",
			"Authorization",
			"X-Requested-With",
			"Accept",
		},
		MaxAge: 3600, // 1 hour
	}
}

// CORSMiddleware wraps an http.Handler with CORS headers
func CORSMiddleware(config *CORSConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get origin from request
		origin := r.Header.Get("Origin")

		// Set Access-Control-Allow-Origin
		if len(config.AllowedOrigins) > 0 {
			if contains(config.AllowedOrigins, "*") {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else if origin != "" && contains(config.AllowedOrigins, origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
		}

		// Set Access-Control-Allow-Credentials
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Set Access-Control-Allow-Methods
		if len(config.AllowedMethods) > 0 {
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
		}

		// Set Access-Control-Allow-Headers
		if len(config.AllowedHeaders) > 0 {
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
		}

		// Set Access-Control-Max-Age
		if config.MaxAge > 0 {
			w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", config.MaxAge))
		}

		// Handle preflight OPTIONS request
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Call next handler
		next.ServeHTTP(w, r)
	})
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
