package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/allsmog/zkdpop-go/pkg/dpop"
	"github.com/allsmog/zkdpop-go/pkg/jwt"
)

// ContextKey is used for storing values in context
type ContextKey string

const (
	// DPoPResultKey is the context key for DPoP verification results
	DPoPResultKey ContextKey = "dpop_result"
	
	// JWTClaimsKey is the context key for JWT claims
	JWTClaimsKey ContextKey = "jwt_claims"
)

// DPoPMiddleware creates middleware for DPoP verification
func DPoPMiddleware(replayStore dpop.ReplayStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify DPoP proof
			result, err := dpop.VerifyDPoP(r, replayStore)
			if err != nil {
				http.Error(w, fmt.Sprintf("DPoP verification failed: %v", err), http.StatusUnauthorized)
				return
			}

			// Add result to context
			ctx := context.WithValue(r.Context(), DPoPResultKey, result)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// JWTMiddleware creates middleware for JWT verification
func JWTMiddleware(issuerJWKS jwk.Set, expectedAudience string) func(http.Handler) http.Handler {
	verifier := jwt.NewJWTVerifier(issuerJWKS)
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract JWT from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "missing Authorization header", http.StatusUnauthorized)
				return
			}

			// Check Bearer prefix
			const bearerPrefix = "Bearer "
			if !strings.HasPrefix(authHeader, bearerPrefix) {
				http.Error(w, "invalid Authorization header format", http.StatusUnauthorized)
				return
			}

			token := strings.TrimPrefix(authHeader, bearerPrefix)

			// Verify JWT
			claims, err := verifier.Verify(token, expectedAudience)
			if err != nil {
				http.Error(w, fmt.Sprintf("JWT verification failed: %v", err), http.StatusUnauthorized)
				return
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), JWTClaimsKey, claims)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// BindJWTToDPoPMiddleware creates middleware that ensures JWT cnf.jkt matches DPoP JWK thumbprint
func BindJWTToDPoPMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get DPoP result from context
			dpopResult, ok := r.Context().Value(DPoPResultKey).(*dpop.DPoPResult)
			if !ok {
				http.Error(w, "DPoP verification required", http.StatusInternalServerError)
				return
			}

			// Get JWT claims from context
			claims, ok := r.Context().Value(JWTClaimsKey).(*jwt.Claims)
			if !ok {
				http.Error(w, "JWT verification required", http.StatusInternalServerError)
				return
			}

			// Check cnf.jkt binding
			if claims.Cnf == nil || claims.Cnf.JKT == "" {
				http.Error(w, "JWT missing cnf.jkt claim", http.StatusForbidden)
				return
			}

			if claims.Cnf.JKT != dpopResult.JKT {
				http.Error(w, "JWT cnf.jkt does not match DPoP JWK thumbprint", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CombinedMiddleware creates middleware that verifies both DPoP and JWT with binding
func CombinedMiddleware(replayStore dpop.ReplayStore, issuerJWKS jwk.Set, expectedAudience string) func(http.Handler) http.Handler {
	dpopMW := DPoPMiddleware(replayStore)
	jwtMW := JWTMiddleware(issuerJWKS, expectedAudience)
	bindMW := BindJWTToDPoPMiddleware()

	return func(next http.Handler) http.Handler {
		return dpopMW(jwtMW(bindMW(next)))
	}
}

// GetDPoPResult extracts DPoP result from request context
func GetDPoPResult(r *http.Request) (*dpop.DPoPResult, bool) {
	result, ok := r.Context().Value(DPoPResultKey).(*dpop.DPoPResult)
	return result, ok
}

// GetJWTClaims extracts JWT claims from request context
func GetJWTClaims(r *http.Request) (*jwt.Claims, bool) {
	claims, ok := r.Context().Value(JWTClaimsKey).(*jwt.Claims)
	return claims, ok
}

// RequireZKScheme middleware ensures the JWT was issued via ZK authentication
func RequireZKScheme(expectedScheme string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetJWTClaims(r)
			if !ok {
				http.Error(w, "JWT claims required", http.StatusInternalServerError)
				return
			}

			if claims.ZK == nil {
				http.Error(w, "JWT missing ZK claims", http.StatusForbidden)
				return
			}

			if claims.ZK.Scheme != expectedScheme {
				http.Error(w, fmt.Sprintf("invalid ZK scheme: expected %s, got %s", expectedScheme, claims.ZK.Scheme), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireCurve middleware ensures the JWT was issued for a specific curve
func RequireCurve(expectedCurve string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetJWTClaims(r)
			if !ok {
				http.Error(w, "JWT claims required", http.StatusInternalServerError)
				return
			}

			if claims.ZK == nil {
				http.Error(w, "JWT missing ZK claims", http.StatusForbidden)
				return
			}

			if claims.ZK.Group != expectedCurve {
				http.Error(w, fmt.Sprintf("invalid curve: expected %s, got %s", expectedCurve, claims.ZK.Group), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CORS middleware for development
func CORS(next http.Handler) http.Handler {
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
}

// RequestID middleware adds a request ID to each request
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			// Generate a simple request ID
			requestID = fmt.Sprintf("%d", r.Context().Value("request_time"))
		}

		w.Header().Set("X-Request-ID", requestID)
		
		ctx := context.WithValue(r.Context(), "request_id", requestID)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// Recovery middleware recovers from panics
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}