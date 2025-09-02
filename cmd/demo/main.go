package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"time"

	"github.com/zkdpop/zkdpop-go/pkg/auth"
	"github.com/zkdpop/zkdpop-go/pkg/crypto/curve"
	"github.com/zkdpop/zkdpop-go/pkg/dpop"
	"github.com/zkdpop/zkdpop-go/pkg/jwt"
	"github.com/zkdpop/zkdpop-go/pkg/middleware"
	"github.com/zkdpop/zkdpop-go/pkg/storage"
)

//go:embed static/*
var staticFiles embed.FS

func main() {
	fmt.Println("🚀 Starting zkDPoP Demo Application...")

	// Initialize storage
	store := storage.NewMemoryStore()
	replayStore := dpop.NewInMemoryReplayStore(5 * time.Minute)
	
	// Initialize curve
	crv := curve.NewSecp256k1()
	
	// Generate JWT signing key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate JWT signing key: %v", err)
	}
	
	tokenSigner, err := jwt.NewES256Signer(privKey, "demo-key", "https://demo.zkdpop.com")
	if err != nil {
		log.Fatalf("Failed to create token signer: %v", err)
	}
	
	// Auth configuration
	config := auth.Config{
		Issuer:     "https://demo.zkdpop.com",
		Audience:   "demo-api",
		TokenTTL:   15 * time.Minute,
		SessionTTL: 2 * time.Minute,
	}
	
	// Create auth handlers
	authHandlers := auth.NewHandlers(store, crv, tokenSigner, replayStore, config)
	
	// Setup routes
	mux := http.NewServeMux()
	
	// Static files (UI)
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("Failed to create static file system: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))
	
	// Auth endpoints
	mux.HandleFunc("/api/register", corsHandler(authHandlers.Register))
	mux.HandleFunc("/api/auth/zk/commit", corsHandler(authHandlers.StartCommit))
	mux.HandleFunc("/api/auth/zk/complete", corsHandler(authHandlers.Complete))
	mux.HandleFunc("/.well-known/jwks.json", corsHandler(authHandlers.JWKS))
	
	// Protected API endpoint for testing
	protectedHandler := middleware.CombinedMiddleware(
		replayStore,
		tokenSigner.JWKS(),
		config.Audience,
	)(http.HandlerFunc(protectedEndpoint))
	mux.Handle("/api/protected", corsMiddleware(protectedHandler))
	
	// Demo info endpoint
	mux.HandleFunc("/api/info", corsHandler(demoInfoHandler))
	
	// Admin endpoints for demo
	mux.HandleFunc("/api/admin/users", corsHandler(func(w http.ResponseWriter, r *http.Request) {
		users, err := store.ListUsers()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"users": %d}`, len(users))
	}))
	
	// Start server
	port := ":8081"
	fmt.Printf("📡 Demo server running at http://localhost%s\n", port)
	fmt.Println("🔐 Open your browser and try the zkDPoP authentication demo!")
	
	if err := http.ListenAndServe(port, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func corsHandler(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, DPoP")
		
		// Handle preflight
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, DPoP")
		
		// Handle preflight
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	// Get auth context
	dpopResult, _ := middleware.GetDPoPResult(r)
	claims, _ := middleware.GetJWTClaims(r)
	
	w.Header().Set("Content-Type", "application/json")
	
	response := fmt.Sprintf(`{
		"message": "✅ Authentication successful!",
		"user_id": "%s",
		"zk_scheme": "%s",
		"zk_group": "%s",
		"dpop_jkt": "%s",
		"issued_at": %d,
		"expires_at": %d
	}`, claims.Subject, claims.ZK.Scheme, claims.ZK.Group, dpopResult.JKT, claims.IssuedAt, claims.ExpiresAt)
	
	w.Write([]byte(response))
}

func demoInfoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	info := `{
		"title": "zkDPoP Demo",
		"description": "Interactive demo of zero-knowledge Demonstration of Proof-of-Possession authentication",
		"features": [
			"Schnorr identification over secp256k1",
			"DPoP-bound JWTs (RFC 9449)",
			"Sender-constrained tokens (RFC 7800)",
			"Zero-knowledge authentication",
			"Stateless resource servers"
		],
		"endpoints": {
			"register": "/api/register",
			"commit": "/api/auth/zk/commit", 
			"complete": "/api/auth/zk/complete",
			"jwks": "/.well-known/jwks.json",
			"protected": "/api/protected"
		}
	}`
	
	w.Write([]byte(info))
}