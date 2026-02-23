package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/allsmog/zkdpop-go/pkg/auth"
	"github.com/allsmog/zkdpop-go/pkg/crypto/curve"
	"github.com/allsmog/zkdpop-go/pkg/dpop"
	"github.com/allsmog/zkdpop-go/pkg/jwt"
	mw "github.com/allsmog/zkdpop-go/pkg/middleware"
	"github.com/allsmog/zkdpop-go/pkg/storage"
)

func main() {
	// Command line flags
	var (
		addr       = flag.String("addr", ":8080", "Server address")
		keyFile    = flag.String("key", "keys/jwt-signing.pem", "JWT signing key file")
		configFile = flag.String("config", "keys/jwt-config.json", "JWT config file")
		issuer     = flag.String("issuer", "https://auth.zkdpop.example", "JWT issuer")
		audience   = flag.String("audience", "zkdpop-api", "JWT audience")
		tokenTTL   = flag.Duration("token-ttl", 5*time.Minute, "JWT token TTL")
		sessionTTL = flag.Duration("session-ttl", 2*time.Minute, "ZK session TTL")
		replayTTL  = flag.Duration("replay-ttl", 5*time.Minute, "DPoP replay cache TTL")
		rateLimit  = flag.Int("rate-limit", 120, "Max requests per minute per client")
		curveName  = flag.String("curve", "secp256k1", "Curve to use (secp256k1|ristretto255)")
	)
	flag.Parse()

	log.Println("Starting zkDPoP Auth Server...")

	// Initialize curve based on flag
	activeCurve, err := curve.FromName(*curveName)
	if err != nil {
		log.Fatalf("Unsupported curve %q: %v", *curveName, err)
	}
	log.Printf("Using curve: %s", activeCurve.Name())
	log.Printf("Rate limit: %d requests/minute per client", *rateLimit)

	// Initialize storage (in-memory for demo)
	var store storage.Store = storage.NewMemoryStore()
	defer store.Close()
	log.Println("Initialized in-memory storage")

	// Initialize DPoP replay store
	replayStore := dpop.NewInMemoryReplayStore(*replayTTL)
	log.Printf("Initialized DPoP replay store with %v TTL", *replayTTL)

	// Initialize JWT signer
	var tokenSigner jwt.TokenSigner

	// Check if key files exist
	if _, err := os.Stat(*keyFile); os.IsNotExist(err) {
		log.Printf("Key file %s does not exist, generating new key...", *keyFile)

		// Generate new key pair
		if err := jwt.GenerateKeyPairFiles("ecdsa", "auth-key-1", *issuer, *keyFile, *configFile); err != nil {
			log.Fatalf("Failed to generate key pair: %v", err)
		}
		log.Printf("Generated new key pair: %s, %s", *keyFile, *configFile)
	}

	// Load JWT signer from files
	tokenSigner, err = jwt.NewES256SignerFromFile(*keyFile, *configFile)
	if err != nil {
		log.Fatalf("Failed to create JWT signer: %v", err)
	}
	log.Printf("Loaded JWT signer with algorithm: %s", tokenSigner.Algorithm())

	// Create auth handlers
	authConfig := auth.Config{
		Issuer:     *issuer,
		Audience:   *audience,
		TokenTTL:   *tokenTTL,
		SessionTTL: *sessionTTL,
	}
	handlers := auth.NewHandlers(store, activeCurve, tokenSigner, replayStore, authConfig)

	// Setup router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(mw.RateLimit(*rateLimit, time.Minute))

	// CORS for development
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, DPoP")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	})

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok","service":"zkdpop-authd"}`)
	})

	// Auth routes
	r.Post("/register", handlers.Register)

	// ZK login routes (require DPoP)
	r.Route("/auth/zk", func(r chi.Router) {
		// Apply DPoP middleware to auth endpoints
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify DPoP for auth endpoints
				if r.Header.Get("DPoP") == "" {
					http.Error(w, "DPoP header required for auth endpoints", http.StatusBadRequest)
					return
				}
				next.ServeHTTP(w, r)
			})
		})

		r.Post("/commit", handlers.StartCommit)
		r.Post("/complete", handlers.Complete)
	})

	// JWKS endpoint
	r.Get("/.well-known/jwks.json", handlers.JWKS)

	// Admin routes (no auth for demo)
	r.Route("/admin", func(r chi.Router) {
		r.Get("/users", func(w http.ResponseWriter, r *http.Request) {
			users, err := store.ListUsers()
			if err != nil {
				http.Error(w, "Failed to list users", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"users":%d,"data":%v}`, len(users), users)
		})

		r.Get("/stats", func(w http.ResponseWriter, r *http.Request) {
			if memStore, ok := store.(*storage.MemoryStore); ok {
				stats := memStore.Stats()
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"storage":%v}`, stats)
			} else {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"storage":"unavailable"}`)
			}
		})
	})

	// Start server
	log.Printf("Server starting on %s", *addr)
	log.Printf("Issuer: %s", *issuer)
	log.Printf("Audience: %s", *audience)
	log.Printf("Token TTL: %v", *tokenTTL)
	log.Printf("Session TTL: %v", *sessionTTL)
	log.Println()
	log.Println("Endpoints:")
	log.Println("  POST /register                - Register new user")
	log.Println("  POST /auth/zk/commit         - Start ZK login (requires DPoP)")
	log.Println("  POST /auth/zk/complete       - Complete ZK login (requires DPoP)")
	log.Println("  GET  /.well-known/jwks.json - JWT signing keys")
	log.Println("  GET  /health                 - Health check")
	log.Println("  GET  /admin/users            - List users")
	log.Println("  GET  /admin/stats            - Storage stats")
	log.Println()

	if err := http.ListenAndServe(*addr, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
