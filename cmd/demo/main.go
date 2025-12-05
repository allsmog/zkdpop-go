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

	// Failure scenario demo endpoints
	// These explain what happens when authentication fails in different ways
	mux.HandleFunc("/api/demo/fail/invalid-proof", corsHandler(failureInvalidProofHandler))
	mux.HandleFunc("/api/demo/fail/dpop-mismatch", corsHandler(failureDPoPMismatchHandler))
	mux.HandleFunc("/api/demo/fail/expired-session", corsHandler(failureExpiredSessionHandler))
	mux.HandleFunc("/api/demo/fail/replay-attack", corsHandler(failureReplayAttackHandler))
	mux.HandleFunc("/api/demo/fail/missing-dpop", corsHandler(failureMissingDPoPHandler))

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
		},
		"failure_demos": {
			"invalid_proof": "/api/demo/fail/invalid-proof",
			"dpop_mismatch": "/api/demo/fail/dpop-mismatch",
			"expired_session": "/api/demo/fail/expired-session",
			"replay_attack": "/api/demo/fail/replay-attack",
			"missing_dpop": "/api/demo/fail/missing-dpop"
		}
	}`

	w.Write([]byte(info))
}

// ============================================================================
// FAILURE SCENARIO DEMONSTRATIONS
// These endpoints demonstrate what happens when authentication fails
// ============================================================================

// failureInvalidProofHandler demonstrates what happens when the Schnorr proof is invalid
// This simulates an attacker trying to authenticate without knowing the private key
func failureInvalidProofHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := `{
		"scenario": "Invalid Schnorr Proof",
		"description": "Demonstrates what happens when someone tries to authenticate without knowing the private key",
		"what_happens": [
			"1. Attacker generates random T (commitment) without knowing r",
			"2. Attacker receives challenge c from server",
			"3. Attacker cannot compute valid s = r + c*x (doesn't know r or x)",
			"4. Attacker sends random/guessed s value",
			"5. Server checks: s*G != T + c*PK",
			"6. Verification FAILS - proof rejected"
		],
		"error_returned": "invalid Schnorr proof",
		"http_status": 401,
		"security_note": "Without the private key, an attacker would need to solve the discrete log problem to forge a proof - computationally infeasible with current technology",
		"math_explanation": {
			"verification_equation": "s*G == T + c*PK",
			"why_it_fails": "Random s gives random s*G, which won't equal T + c*PK",
			"probability_of_guess": "1 in ~2^256 (effectively zero)"
		}
	}`

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))
}

// failureDPoPMismatchHandler demonstrates DPoP key binding protection
// This simulates an attacker who stole a token trying to use it with their own DPoP key
func failureDPoPMismatchHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := `{
		"scenario": "DPoP Key Mismatch",
		"description": "Demonstrates sender-constrained token protection - stolen tokens can't be used",
		"what_happens": [
			"1. Legitimate user authenticates and gets JWT with cnf.jkt claim",
			"2. Attacker steals the JWT token",
			"3. Attacker creates DPoP proof with their OWN keypair",
			"4. Attacker sends request with stolen JWT + their DPoP proof",
			"5. Server computes JKT from attacker's DPoP proof",
			"6. Server compares: attacker's JKT != JWT's cnf.jkt",
			"7. Request REJECTED - token bound to different key"
		],
		"error_returned": "DPoP key mismatch",
		"http_status": 401,
		"security_note": "Even with a valid token, the attacker cannot use it without the original user's DPoP private key",
		"cnf_claim_example": {
			"cnf": {
				"jkt": "sha256-thumbprint-of-legitimate-users-dpop-key"
			}
		}
	}`

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))
}

// failureExpiredSessionHandler demonstrates time-based session protection
func failureExpiredSessionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := `{
		"scenario": "Expired Session",
		"description": "Demonstrates time-based protection against delayed attacks",
		"what_happens": [
			"1. User starts authentication (commit phase)",
			"2. Server creates session with 2-minute TTL",
			"3. User doesn't complete authentication in time",
			"4. User tries to complete after session expires",
			"5. Server checks: time.Since(session.Timeslice) > SessionTTL",
			"6. Request REJECTED - session expired"
		],
		"error_returned": "session expired",
		"http_status": 410,
		"timing": {
			"session_ttl": "2 minutes",
			"timeslice_granularity": "1 minute",
			"purpose": "Prevents attackers from stockpiling challenges for later use"
		},
		"security_note": "Tight time windows limit the attack surface for replay and delay attacks"
	}`

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))
}

// failureReplayAttackHandler demonstrates replay protection
func failureReplayAttackHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := `{
		"scenario": "Replay Attack Blocked",
		"description": "Demonstrates protection against reusing captured DPoP proofs",
		"what_happens": [
			"1. Attacker captures a valid DPoP proof from network traffic",
			"2. Attacker replays the exact same proof in a new request",
			"3. Server checks replay store for (jkt, jti, htm, htu, minute) tuple",
			"4. Server finds: this exact proof was already used!",
			"5. Request REJECTED - replay attack detected"
		],
		"error_returned": "DPoP proof replay detected",
		"http_status": 401,
		"replay_store_key": {
			"jkt": "thumbprint of DPoP public key",
			"jti": "unique JWT ID from the proof",
			"htm": "HTTP method (GET, POST, etc)",
			"htu": "HTTP URI",
			"minute": "timestamp bucket (per-minute granularity)"
		},
		"security_note": "Each DPoP proof can only be used once. Even a network attacker who captures proofs cannot replay them."
	}`

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))
}

// failureMissingDPoPHandler demonstrates what happens with no DPoP proof
func failureMissingDPoPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := `{
		"scenario": "Missing DPoP Proof",
		"description": "Demonstrates that tokens alone are not sufficient for protected resources",
		"what_happens": [
			"1. User has valid JWT token",
			"2. User sends request WITHOUT DPoP header",
			"3. Server checks for DPoP header: not found",
			"4. Request REJECTED - DPoP proof required"
		],
		"error_returned": "missing DPoP header",
		"http_status": 401,
		"security_note": "Protected endpoints require BOTH a valid JWT AND a valid DPoP proof. This prevents bearer token attacks.",
		"required_headers": {
			"Authorization": "Bearer <jwt-token>",
			"DPoP": "<dpop-proof-jwt>"
		}
	}`

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))
}