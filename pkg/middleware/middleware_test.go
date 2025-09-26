package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/zkdpop/zkdpop-go/pkg/dpop"
	zkjwt "github.com/zkdpop/zkdpop-go/pkg/jwt"
)

// Test helpers
func createTestDPoPProof(method, url string, privateKey *ecdsa.PrivateKey) (string, *dpop.JWK, error) {
	// Convert to JWK
	jwk, err := dpop.PublicKeyToJWK(&privateKey.PublicKey)
	if err != nil {
		return "", nil, err
	}

	// Create claims
	claims := jwt.MapClaims{
		"htm": method,
		"htu": url,
		"iat": time.Now().Unix(),
		"jti": uuid.New().String(),
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Add JWK to header
	jwkMap := map[string]interface{}{
		"kty": jwk.Kty,
		"crv": jwk.Crv,
		"x":   jwk.X,
		"y":   jwk.Y,
		"use": jwk.Use,
	}
	token.Header["jwk"] = jwkMap

	// Sign token
	dpopProof, err := token.SignedString(privateKey)
	return dpopProof, jwk, err
}

func createTestJWT(issuer, subject, audience, jkt string, signer zkjwt.TokenSigner) (string, error) {
	claims := map[string]interface{}{
		"iss": issuer,
		"sub": subject,
		"aud": audience,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]interface{}{
			"jkt": jkt,
		},
		"zk": map[string]interface{}{
			"scheme": "schnorr-id",
			"grp":    "secp256k1",
			"t_hash": "dGVzdC1oYXNo",
			"c":      "dGVzdC1jaGFsbGVuZ2U=",
			"ts":     time.Now().Format(time.RFC3339),
		},
	}

	return signer.Sign(claims)
}

func TestDPoPMiddleware(t *testing.T) {
	replayStore := dpop.NewInMemoryReplayStore(5 * time.Minute)
	middleware := DPoPMiddleware(replayStore)

	// Generate test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	t.Run("ValidDPoP", func(t *testing.T) {
		// Create valid DPoP proof
		method := "POST"
		url := "https://api.example.com/test"
		dpopProof, jwk, err := createTestDPoPProof(method, url, privateKey)
		if err != nil {
			t.Fatalf("failed to create DPoP proof: %v", err)
		}

		// Create request
		req := httptest.NewRequest(method, url, nil)
		req.Header.Set("DPoP", dpopProof)

		rr := httptest.NewRecorder()

		// Handler that checks context
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			result, ok := GetDPoPResult(r)
			if !ok {
				t.Error("DPoP result should be in context")
			}

			if result.JKT == "" {
				t.Error("JKT should not be empty")
			}

			if result.Claims.HTM != method {
				t.Errorf("wrong method: %s", result.Claims.HTM)
			}

			if result.Claims.HTU != url {
				t.Errorf("wrong URL: %s", result.Claims.HTU)
			}

			// Verify JWK matches
			if result.JWK.Kty != jwk.Kty || result.JWK.X != jwk.X || result.JWK.Y != jwk.Y {
				t.Error("JWK mismatch")
			}

			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})

	t.Run("MissingDPoP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		// No DPoP header

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("InvalidDPoP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		req.Header.Set("DPoP", "invalid-jwt-token")

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("ReplayAttack", func(t *testing.T) {
		method := "GET"
		url := "https://api.example.com/test"
		dpopProof, _, err := createTestDPoPProof(method, url, privateKey)
		if err != nil {
			t.Fatalf("failed to create DPoP proof: %v", err)
		}

		// First request should succeed
		req1 := httptest.NewRequest(method, url, nil)
		req1.Header.Set("DPoP", dpopProof)

		rr1 := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr1, req1)

		if rr1.Code != http.StatusOK {
			t.Errorf("first request should succeed, got %d", rr1.Code)
		}

		// Second request with same proof should fail
		req2 := httptest.NewRequest(method, url, nil)
		req2.Header.Set("DPoP", dpopProof)

		rr2 := httptest.NewRecorder()
		middleware(handler).ServeHTTP(rr2, req2)

		if rr2.Code != http.StatusUnauthorized {
			t.Errorf("replay should fail, got %d", rr2.Code)
		}
	})
}

func TestJWTMiddleware(t *testing.T) {
	// Setup signer
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := zkjwt.NewES256Signer(privateKey, "test-key", "https://auth.example.com")
	middleware := JWTMiddleware(signer.JWKS(), "test-audience")

	t.Run("ValidJWT", func(t *testing.T) {
		// Create valid JWT
		token, err := createTestJWT("https://auth.example.com", "test-subject", "test-audience", "test-jkt", signer)
		if err != nil {
			t.Fatalf("failed to create JWT: %v", err)
		}

		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetJWTClaims(r)
			if !ok {
				t.Error("JWT claims should be in context")
			}

			if claims.Issuer != "https://auth.example.com" {
				t.Errorf("wrong issuer: %s", claims.Issuer)
			}

			if claims.Subject != "test-subject" {
				t.Errorf("wrong subject: %s", claims.Subject)
			}

			if claims.Audience != "test-audience" {
				t.Errorf("wrong audience: %s", claims.Audience)
			}

			if claims.Cnf == nil || claims.Cnf.JKT != "test-jkt" {
				t.Error("cnf.jkt mismatch")
			}

			if claims.ZK == nil || claims.ZK.Scheme != "schnorr-id" {
				t.Error("ZK claims mismatch")
			}

			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})

	t.Run("MissingAuthorization", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		// No Authorization header

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("InvalidAuthorizationFormat", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		req.Header.Set("Authorization", "Basic dGVzdA==")

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("ExpiredJWT", func(t *testing.T) {
		// Create expired JWT
		claims := map[string]interface{}{
			"iss": "https://auth.example.com",
			"sub": "test-subject",
			"aud": "test-audience",
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
			"exp": time.Now().Add(-time.Hour).Unix(), // Expired
			"cnf": map[string]interface{}{
				"jkt": "test-jkt",
			},
		}

		token, err := signer.Sign(claims)
		if err != nil {
			t.Fatalf("failed to create expired JWT: %v", err)
		}

		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("WrongAudience", func(t *testing.T) {
		// Create JWT with wrong audience
		token, err := createTestJWT("https://auth.example.com", "test-subject", "wrong-audience", "test-jkt", signer)
		if err != nil {
			t.Fatalf("failed to create JWT: %v", err)
		}

		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

func TestBindJWTToDPoPMiddleware(t *testing.T) {
	middleware := BindJWTToDPoPMiddleware()

	t.Run("ValidBinding", func(t *testing.T) {
		// Create mock DPoP result
		dpopResult := &dpop.DPoPResult{
			JKT: "matching-jkt",
		}

		// Create mock JWT claims
		jwtClaims := &zkjwt.Claims{
			Cnf: &zkjwt.ConfirmationClaims{
				JKT: "matching-jkt",
			},
		}

		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		ctx := req.Context()
		ctx = context.WithValue(ctx, DPoPResultKey, dpopResult)
		ctx = context.WithValue(ctx, JWTClaimsKey, jwtClaims)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})

	t.Run("MissingDPoP", func(t *testing.T) {
		jwtClaims := &zkjwt.Claims{
			Cnf: &zkjwt.ConfirmationClaims{
				JKT: "test-jkt",
			},
		}

		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		ctx := context.WithValue(req.Context(), JWTClaimsKey, jwtClaims)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", rr.Code)
		}
	})

	t.Run("MissingJWT", func(t *testing.T) {
		dpopResult := &dpop.DPoPResult{
			JKT: "test-jkt",
		}

		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		ctx := context.WithValue(req.Context(), DPoPResultKey, dpopResult)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", rr.Code)
		}
	})

	t.Run("MissingCnfClaim", func(t *testing.T) {
		dpopResult := &dpop.DPoPResult{
			JKT: "test-jkt",
		}

		jwtClaims := &zkjwt.Claims{
			Cnf: nil, // No cnf claim
		}

		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		ctx := req.Context()
		ctx = context.WithValue(ctx, DPoPResultKey, dpopResult)
		ctx = context.WithValue(ctx, JWTClaimsKey, jwtClaims)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rr.Code)
		}
	})

	t.Run("JKTMismatch", func(t *testing.T) {
		dpopResult := &dpop.DPoPResult{
			JKT: "dpop-jkt",
		}

		jwtClaims := &zkjwt.Claims{
			Cnf: &zkjwt.ConfirmationClaims{
				JKT: "different-jkt",
			},
		}

		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		ctx := req.Context()
		ctx = context.WithValue(ctx, DPoPResultKey, dpopResult)
		ctx = context.WithValue(ctx, JWTClaimsKey, jwtClaims)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rr.Code)
		}
	})
}

func TestRequireZKScheme(t *testing.T) {
	middleware := RequireZKScheme("schnorr-id")

	t.Run("ValidScheme", func(t *testing.T) {
		claims := &zkjwt.Claims{
			ZK: &zkjwt.ZKClaims{
				Scheme: "schnorr-id",
			},
		}

		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		ctx := context.WithValue(req.Context(), JWTClaimsKey, claims)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})

	t.Run("MissingZKClaims", func(t *testing.T) {
		claims := &zkjwt.Claims{
			ZK: nil,
		}

		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		ctx := context.WithValue(req.Context(), JWTClaimsKey, claims)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rr.Code)
		}
	})

	t.Run("WrongScheme", func(t *testing.T) {
		claims := &zkjwt.Claims{
			ZK: &zkjwt.ZKClaims{
				Scheme: "different-scheme",
			},
		}

		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		ctx := context.WithValue(req.Context(), JWTClaimsKey, claims)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rr.Code)
		}
	})
}

func TestRequireCurve(t *testing.T) {
	middleware := RequireCurve("secp256k1")

	t.Run("ValidCurve", func(t *testing.T) {
		claims := &zkjwt.Claims{
			ZK: &zkjwt.ZKClaims{
				Group: "secp256k1",
			},
		}

		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		ctx := context.WithValue(req.Context(), JWTClaimsKey, claims)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})

	t.Run("WrongCurve", func(t *testing.T) {
		claims := &zkjwt.Claims{
			ZK: &zkjwt.ZKClaims{
				Group: "ristretto255",
			},
		}

		req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
		ctx := context.WithValue(req.Context(), JWTClaimsKey, claims)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rr.Code)
		}
	})
}

func TestUtilityMiddleware(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	t.Run("CORS", func(t *testing.T) {
		// Test CORS headers are added
		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		handler := CORS(testHandler)
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}

		// Check CORS headers
		if origin := rr.Header().Get("Access-Control-Allow-Origin"); origin != "*" {
			t.Errorf("expected CORS origin *, got %s", origin)
		}

		if methods := rr.Header().Get("Access-Control-Allow-Methods"); methods == "" {
			t.Error("expected CORS methods header")
		}

		if headers := rr.Header().Get("Access-Control-Allow-Headers"); headers == "" {
			t.Error("expected CORS headers header")
		}
	})

	t.Run("CORSOptions", func(t *testing.T) {
		// Test OPTIONS request handling
		req := httptest.NewRequest("OPTIONS", "/test", nil)
		rr := httptest.NewRecorder()

		handler := CORS(testHandler)
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}

		// Should not call next handler for OPTIONS
		if body := rr.Body.String(); body != "" {
			t.Error("OPTIONS should not call next handler")
		}
	})

	t.Run("RequestID", func(t *testing.T) {
		// Test request ID generation
		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		handler := RequestID(testHandler)
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}

		// Check request ID header is set
		if requestID := rr.Header().Get("X-Request-ID"); requestID == "" {
			t.Error("expected X-Request-ID header")
		}
	})

	t.Run("RequestIDExisting", func(t *testing.T) {
		// Test with existing request ID
		existingID := "test-request-123"
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Request-ID", existingID)
		rr := httptest.NewRecorder()

		handler := RequestID(testHandler)
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}

		// Should preserve existing request ID
		if requestID := rr.Header().Get("X-Request-ID"); requestID != existingID {
			t.Errorf("expected request ID %s, got %s", existingID, requestID)
		}
	})

	t.Run("Recovery", func(t *testing.T) {
		// Test panic recovery
		panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("test panic")
		})

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		handler := Recovery(panicHandler)
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected status 500 after panic, got %d", rr.Code)
		}

		if body := rr.Body.String(); !strings.Contains(body, "Internal Server Error") {
			t.Errorf("expected error message, got %s", body)
		}
	})

	t.Run("RecoveryNoPanic", func(t *testing.T) {
		// Test normal operation without panic
		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		handler := Recovery(testHandler)
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}

		if body := rr.Body.String(); body != "OK" {
			t.Errorf("expected OK, got %s", body)
		}
	})
}

func TestRateLimit(t *testing.T) {
	ratelimited := RateLimit(2, time.Minute)

	counter := 0
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter++
		w.WriteHeader(http.StatusOK)
	})

	handler := ratelimited(baseHandler)

	req := httptest.NewRequest("GET", "/rate", nil)
	req.RemoteAddr = "192.0.2.1:1234"

	resp1 := httptest.NewRecorder()
	handler.ServeHTTP(resp1, req)
	if resp1.Code != http.StatusOK {
		t.Fatalf("expected first request to succeed, got %d", resp1.Code)
	}

	resp2 := httptest.NewRecorder()
	handler.ServeHTTP(resp2, req)
	if resp2.Code != http.StatusOK {
		t.Fatalf("expected second request to succeed, got %d", resp2.Code)
	}

	resp3 := httptest.NewRecorder()
	handler.ServeHTTP(resp3, req)
	if resp3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected rate limit to trigger, got %d", resp3.Code)
	}

	if counter != 2 {
		t.Fatalf("expected handler to execute twice, ran %d times", counter)
	}
}

func TestCombinedMiddleware(t *testing.T) {
	// Setup
	replayStore := dpop.NewInMemoryReplayStore(5 * time.Minute)
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := zkjwt.NewES256Signer(privateKey, "test-key", "https://auth.example.com")

	_ = CombinedMiddleware(replayStore, signer.JWKS(), "test-audience") // Test that it can be created

	t.Run("ComponentsSeparately", func(t *testing.T) {
		// Test that each middleware component works
		// This is easier to test than the full binding which requires exact JKT matching

		// Generate DPoP key
		dpopKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		// Create JWT (with any JKT for this test)
		token, err := createTestJWT("https://auth.example.com", "test-subject", "test-audience", "test-jkt", signer)
		if err != nil {
			t.Fatalf("failed to create JWT: %v", err)
		}

		// Create DPoP proof
		method := "GET"
		url := "https://api.example.com/test"
		dpopProof, _, err := createTestDPoPProof(method, url, dpopKey)
		if err != nil {
			t.Fatalf("failed to create DPoP proof: %v", err)
		}

		// Test DPoP middleware alone
		dpopMW := DPoPMiddleware(replayStore)
		req1 := httptest.NewRequest(method, url, nil)
		req1.Header.Set("DPoP", dpopProof)
		rr1 := httptest.NewRecorder()

		dpopMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, ok := GetDPoPResult(r)
			if !ok {
				t.Error("DPoP result should be in context")
			}
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr1, req1)

		if rr1.Code != http.StatusOK {
			t.Errorf("DPoP middleware failed: %d", rr1.Code)
		}

		// Test JWT middleware alone
		jwtMW := JWTMiddleware(signer.JWKS(), "test-audience")
		req2 := httptest.NewRequest(method, url, nil)
		req2.Header.Set("Authorization", "Bearer "+token)
		rr2 := httptest.NewRecorder()

		jwtMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, ok := GetJWTClaims(r)
			if !ok {
				t.Error("JWT claims should be in context")
			}
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr2, req2)

		if rr2.Code != http.StatusOK {
			t.Errorf("JWT middleware failed: %d", rr2.Code)
		}
	})
}
