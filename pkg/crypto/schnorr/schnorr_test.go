package schnorr

import (
	"encoding/hex"
	"testing"

	"github.com/allsmog/zkdpop-go/pkg/crypto/curve"
)

func TestSchnorrVerification(t *testing.T) {
	crv := curve.NewSecp256k1()

	t.Run("ValidProof", func(t *testing.T) {
		// Generate key pair
		privateKey, err := crv.GenerateScalar()
		if err != nil {
			t.Fatalf("failed to generate private key: %v", err)
		}

		publicKey := crv.ScalarBaseMult(privateKey)
		publicKeyBytes := publicKey.Bytes()

		// Generate commitment
		T, r, err := GenerateCommitment(crv)
		if err != nil {
			t.Fatalf("failed to generate commitment: %v", err)
		}

		// Derive context and challenge
		ctx := DeriveContext("test-aud", "/test", "POST", "2024-01-01T12:00:00Z", []byte("server-ephemeral"))
		challenge, err := DeriveChallenge(crv, T, publicKeyBytes, ctx)
		if err != nil {
			t.Fatalf("failed to derive challenge: %v", err)
		}

		// Parse challenge scalar
		challengeScalar, err := crv.ParseScalar(challenge)
		if err != nil {
			t.Fatalf("failed to parse challenge: %v", err)
		}

		// Compute response
		response, err := ComputeResponse(crv, r, challengeScalar, privateKey)
		if err != nil {
			t.Fatalf("failed to compute response: %v", err)
		}

		// Verify proof
		result, err := VerifySchnorr(crv, publicKeyBytes, T, challenge, response.Bytes())
		if err != nil {
			t.Fatalf("verification failed: %v", err)
		}

		if !result.Valid {
			t.Error("proof should be valid")
		}
	})

	t.Run("InvalidProof", func(t *testing.T) {
		// Generate key pair
		privateKey, _ := crv.GenerateScalar()
		publicKey := crv.ScalarBaseMult(privateKey)
		publicKeyBytes := publicKey.Bytes()

		// Generate commitment
		T, r, _ := GenerateCommitment(crv)

		// Derive challenge
		ctx := DeriveContext("test-aud", "/test", "POST", "2024-01-01T12:00:00Z", []byte("server-ephemeral"))
		challenge, _ := DeriveChallenge(crv, T, publicKeyBytes, ctx)
		challengeScalar, _ := crv.ParseScalar(challenge)

		// Compute response
		response, _ := ComputeResponse(crv, r, challengeScalar, privateKey)

		// Corrupt the response
		responseBytes := response.Bytes()
		responseBytes[0] ^= 1 // Flip a bit

		// Verify should fail
		result, err := VerifySchnorr(crv, publicKeyBytes, T, challenge, responseBytes)
		if err != nil {
			t.Fatalf("verification failed: %v", err)
		}

		if result.Valid {
			t.Error("corrupted proof should be invalid")
		}
	})

	t.Run("WrongPublicKey", func(t *testing.T) {
		// Generate two key pairs
		privateKey1, _ := crv.GenerateScalar()
		privateKey2, _ := crv.GenerateScalar()

		publicKey2 := crv.ScalarBaseMult(privateKey2)
		publicKey2Bytes := publicKey2.Bytes()

		// Generate commitment and response with privateKey1
		T, r, _ := GenerateCommitment(crv)
		
		ctx := DeriveContext("test-aud", "/test", "POST", "2024-01-01T12:00:00Z", []byte("server-ephemeral"))
		challenge, _ := DeriveChallenge(crv, T, publicKey2Bytes, ctx)
		challengeScalar, _ := crv.ParseScalar(challenge)

		response, _ := ComputeResponse(crv, r, challengeScalar, privateKey1)

		// Verify with publicKey2 should fail
		result, err := VerifySchnorr(crv, publicKey2Bytes, T, challenge, response.Bytes())
		if err != nil {
			t.Fatalf("verification failed: %v", err)
		}

		if result.Valid {
			t.Error("proof with wrong public key should be invalid")
		}
	})
}

func TestFullVerifySchnorr(t *testing.T) {
	crv := curve.NewSecp256k1()

	// Generate key pair
	privateKey, _ := crv.GenerateScalar()
	publicKey := crv.ScalarBaseMult(privateKey)
	publicKeyBytes := publicKey.Bytes()

	// Generate commitment
	T, r, _ := GenerateCommitment(crv)

	// Test parameters
	aud := "test-audience"
	path := "/auth/zk/complete"
	method := "POST"
	timeslice := "2024-01-01T12:00:00Z"
	serverEphemeral := []byte("test-server-ephemeral-32-bytes")

	// Derive context and challenge (simulating server)
	ctx := DeriveContext(aud, path, method, timeslice, serverEphemeral)
	challenge, _ := DeriveChallenge(crv, T, publicKeyBytes, ctx)
	challengeScalar, _ := crv.ParseScalar(challenge)

	// Compute response (simulating client)
	response, _ := ComputeResponse(crv, r, challengeScalar, privateKey)

	// Full verification
	result, err := FullVerifySchnorr(crv, publicKeyBytes, T, response.Bytes(), aud, path, method, timeslice, serverEphemeral)
	if err != nil {
		t.Fatalf("full verification failed: %v", err)
	}

	if !result.Valid {
		t.Error("full proof should be valid")
	}

	// Verify context was computed correctly
	expectedCtx := DeriveContext(aud, path, method, timeslice, serverEphemeral)
	if hex.EncodeToString(result.Context) != hex.EncodeToString(expectedCtx) {
		t.Error("context mismatch")
	}
}

func TestDeriveChallenge(t *testing.T) {
	crv := curve.NewSecp256k1()

	// Test vectors
	T := make([]byte, 33)
	T[0] = 0x02 // Compressed point prefix

	PK := make([]byte, 33)
	PK[0] = 0x03

	ctx := []byte("test-context")

	// Derive challenge
	c1, err := DeriveChallenge(crv, T, PK, ctx)
	if err != nil {
		t.Fatalf("failed to derive challenge: %v", err)
	}

	// Should be deterministic
	c2, err := DeriveChallenge(crv, T, PK, ctx)
	if err != nil {
		t.Fatalf("failed to derive second challenge: %v", err)
	}

	if hex.EncodeToString(c1) != hex.EncodeToString(c2) {
		t.Error("challenge derivation should be deterministic")
	}

	// Different context should produce different challenge
	c3, err := DeriveChallenge(crv, T, PK, []byte("different-context"))
	if err != nil {
		t.Fatalf("failed to derive third challenge: %v", err)
	}

	if hex.EncodeToString(c1) == hex.EncodeToString(c3) {
		t.Error("different contexts should produce different challenges")
	}
}

func TestDeriveContext(t *testing.T) {
	// Test parameters
	aud := "test-audience"
	path := "/auth/zk/complete"
	method := "POST"
	timeslice := "2024-01-01T12:00:00Z"
	serverEphemeral := []byte("server-ephemeral-data")

	// Derive context
	ctx1 := DeriveContext(aud, path, method, timeslice, serverEphemeral)
	
	// Should be deterministic
	ctx2 := DeriveContext(aud, path, method, timeslice, serverEphemeral)

	if hex.EncodeToString(ctx1) != hex.EncodeToString(ctx2) {
		t.Error("context derivation should be deterministic")
	}

	// Different parameters should produce different context
	ctx3 := DeriveContext("different-aud", path, method, timeslice, serverEphemeral)

	if hex.EncodeToString(ctx1) == hex.EncodeToString(ctx3) {
		t.Error("different parameters should produce different contexts")
	}
}

func TestGenerateCommitment(t *testing.T) {
	crv := curve.NewSecp256k1()

	T1, r1, err := GenerateCommitment(crv)
	if err != nil {
		t.Fatalf("failed to generate commitment: %v", err)
	}

	if len(T1) != 33 {
		t.Errorf("expected 33-byte commitment, got %d", len(T1))
	}

	// Should generate different commitments
	T2, r2, err := GenerateCommitment(crv)
	if err != nil {
		t.Fatalf("failed to generate second commitment: %v", err)
	}

	if hex.EncodeToString(T1) == hex.EncodeToString(T2) {
		t.Error("commitments should be different")
	}

	if hex.EncodeToString(r1.Bytes()) == hex.EncodeToString(r2.Bytes()) {
		t.Error("randomness should be different")
	}

	// Verify T = r * G
	expectedT := crv.ScalarBaseMult(r1)
	actualT, err := crv.ParsePoint(T1)
	if err != nil {
		t.Fatalf("failed to parse commitment point: %v", err)
	}

	if !expectedT.Equal(actualT) {
		t.Error("commitment point should equal r * G")
	}
}