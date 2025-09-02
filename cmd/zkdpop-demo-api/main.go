package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/zkdpop/zkdpop-go/pkg/dpop"
	mw "github.com/zkdpop/zkdpop-go/pkg/middleware"
)

func main() {
	// Command line flags
	var (
		addr       = flag.String("addr", ":8081", "Server address")
		authServer = flag.String("auth-server", "http://localhost:8080", "Auth server base URL")
		audience   = flag.String("audience", "zkdpop-api", "JWT audience")
		replayTTL  = flag.Duration("replay-ttl", 5*time.Minute, "DPoP replay cache TTL")
	)
	flag.Parse()

	log.Println("Starting zkDPoP Demo API Server...")

	// Initialize DPoP replay store
	replayStore := dpop.NewInMemoryReplayStore(*replayTTL)
	log.Printf("Initialized DPoP replay store with %v TTL", *replayTTL)

	// Fetch JWKS from auth server
	jwksURL := *authServer + "/.well-known/jwks.json"
	log.Printf("Fetching JWKS from: %s", jwksURL)

	resp, err := http.Get(jwksURL)
	if err != nil {
		log.Fatalf("Failed to fetch JWKS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Failed to fetch JWKS: HTTP %d", resp.StatusCode)
	}

	issuerJWKS, err := jwk.ParseReader(resp.Body)
	if err != nil {
		log.Fatalf("Failed to parse JWKS: %v", err)
	}

	log.Printf("Loaded %d signing keys", issuerJWKS.Len())

	// Setup router
	r := chi.NewRouter()

	// Basic middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// CORS for development
	r.Use(mw.CORS)

	// Health check (no auth required)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok","service":"zkdpop-demo-api"}`)
	})

	// Public endpoint (no auth required)
	r.Get("/public", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"message":   "This is a public endpoint",
			"timestamp": time.Now(),
			"service":   "zkdpop-demo-api",
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Protected routes (require DPoP + JWT)
	r.Route("/api", func(r chi.Router) {
		// Apply combined middleware (DPoP + JWT + binding)
		r.Use(mw.CombinedMiddleware(replayStore, issuerJWKS, *audience))

		// Profile endpoint
		r.Get("/profile", func(w http.ResponseWriter, r *http.Request) {
			// Get JWT claims from context
			claims, ok := mw.GetJWTClaims(r)
			if !ok {
				http.Error(w, "Missing JWT claims", http.StatusInternalServerError)
				return
			}

			// Get DPoP result from context
			dpopResult, ok := mw.GetDPoPResult(r)
			if !ok {
				http.Error(w, "Missing DPoP result", http.StatusInternalServerError)
				return
			}

			response := map[string]interface{}{
				"message":   "Profile data",
				"subject":   claims.Subject,
				"audience":  claims.Audience,
				"issued_at": claims.IssuedAt,
				"expires_at": claims.ExpiresAt,
				"dpop_jkt":  dpopResult.JKT,
				"zk_info":   claims.ZK,
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		})

		// Orders endpoint
		r.Get("/orders", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := mw.GetJWTClaims(r)
			
			// Mock orders data
			orders := []map[string]interface{}{
				{
					"id":     "order_001",
					"amount": 99.99,
					"status": "completed",
					"user":   claims.Subject,
				},
				{
					"id":     "order_002", 
					"amount": 149.50,
					"status": "pending",
					"user":   claims.Subject,
				},
			}

			response := map[string]interface{}{
				"orders":    orders,
				"timestamp": time.Now(),
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		})

		// Secure endpoint (requires specific ZK scheme)
		r.Route("/secure", func(r chi.Router) {
			r.Use(mw.RequireZKScheme("schnorr-id"))

			r.Get("/data", func(w http.ResponseWriter, r *http.Request) {
				claims, _ := mw.GetJWTClaims(r)
				
				response := map[string]interface{}{
					"message":    "This endpoint requires Schnorr ZK authentication",
					"subject":    claims.Subject,
					"zk_scheme":  claims.ZK.Scheme,
					"zk_group":   claims.ZK.Group,
					"timeslice":  claims.ZK.Timeslice,
					"timestamp":  time.Now(),
					"secret_data": "Only accessible via ZK proof",
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			})
		})

		// Secp256k1-only endpoint
		r.Route("/secp256k1", func(r chi.Router) {
			r.Use(mw.RequireCurve("secp256k1"))

			r.Get("/bitcoin-data", func(w http.ResponseWriter, r *http.Request) {
				claims, _ := mw.GetJWTClaims(r)
				
				response := map[string]interface{}{
					"message":     "This endpoint requires secp256k1 authentication",
					"subject":     claims.Subject,
					"curve":       claims.ZK.Group,
					"bitcoin_data": "Mock Bitcoin-related data",
					"timestamp":   time.Now(),
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			})
		})
	})

	// Demo information endpoint
	r.Get("/info", func(w http.ResponseWriter, r *http.Request) {
		info := map[string]interface{}{
			"service":     "zkDPoP Demo API",
			"description": "Demonstrates zkDPoP authentication with DPoP-bound JWTs",
			"auth_server": *authServer,
			"audience":    *audience,
			"endpoints": map[string]interface{}{
				"public": map[string]string{
					"GET /health":  "Health check",
					"GET /public":  "Public endpoint (no auth)",
					"GET /info":    "This information",
				},
				"protected": map[string]string{
					"GET /api/profile":           "User profile (requires DPoP + JWT)",
					"GET /api/orders":            "User orders (requires DPoP + JWT)",
					"GET /api/secure/data":       "Secure data (requires Schnorr ZK)",
					"GET /api/secp256k1/bitcoin-data": "Bitcoin data (requires secp256k1)",
				},
			},
			"auth_flow": []string{
				"1. Register user: POST /register",
				"2. Start ZK login: POST /auth/zk/commit (with DPoP)",
				"3. Complete ZK login: POST /auth/zk/complete (with DPoP)",
				"4. Use JWT + DPoP for API calls",
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	})

	// Start server
	log.Printf("Server starting on %s", *addr)
	log.Printf("Auth server: %s", *authServer)
	log.Printf("Expected audience: %s", *audience)
	log.Println()
	log.Println("Endpoints:")
	log.Println("  GET  /health                      - Health check")
	log.Println("  GET  /public                      - Public endpoint")
	log.Println("  GET  /info                        - API information")
	log.Println("  GET  /api/profile                 - User profile (DPoP + JWT)")
	log.Println("  GET  /api/orders                  - User orders (DPoP + JWT)")
	log.Println("  GET  /api/secure/data             - Secure data (Schnorr ZK)")
	log.Println("  GET  /api/secp256k1/bitcoin-data  - Bitcoin data (secp256k1)")
	log.Println()
	log.Printf("Visit http://localhost%s/info for more details", *addr)

	if err := http.ListenAndServe(*addr, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}