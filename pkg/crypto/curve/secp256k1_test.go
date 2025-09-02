package curve

import (
	"encoding/hex"
	"testing"
)

func TestSecp256k1Curve(t *testing.T) {
	curve := NewSecp256k1()

	t.Run("Name", func(t *testing.T) {
		if curve.Name() != "secp256k1" {
			t.Errorf("expected curve name 'secp256k1', got %s", curve.Name())
		}
	})

	t.Run("GenerateScalar", func(t *testing.T) {
		s1, err := curve.GenerateScalar()
		if err != nil {
			t.Fatalf("failed to generate scalar: %v", err)
		}

		s2, err := curve.GenerateScalar()
		if err != nil {
			t.Fatalf("failed to generate second scalar: %v", err)
		}

		// Scalars should be different
		if string(s1.Bytes()) == string(s2.Bytes()) {
			t.Error("generated scalars should be different")
		}

		// Scalar should be in range [1, n-1]
		if s1.BigInt().Sign() <= 0 {
			t.Error("scalar should be positive")
		}

		if s1.BigInt().Cmp(curve.Order()) >= 0 {
			t.Error("scalar should be less than curve order")
		}
	})

	t.Run("ScalarBaseMult", func(t *testing.T) {
		// Test with known scalar
		scalar, err := curve.GenerateScalar()
		if err != nil {
			t.Fatalf("failed to generate scalar: %v", err)
		}

		point := curve.ScalarBaseMult(scalar)
		if point == nil {
			t.Fatal("ScalarBaseMult returned nil")
		}

		if point.IsIdentity() {
			t.Error("point should not be identity")
		}

		// Validate the point
		if err := curve.ValidatePoint(point); err != nil {
			t.Errorf("invalid point: %v", err)
		}
	})

	t.Run("ParsePoint", func(t *testing.T) {
		// Generate a point
		scalar, _ := curve.GenerateScalar()
		originalPoint := curve.ScalarBaseMult(scalar)
		pointBytes := originalPoint.Bytes()

		// Parse it back
		parsedPoint, err := curve.ParsePoint(pointBytes)
		if err != nil {
			t.Fatalf("failed to parse point: %v", err)
		}

		// Should be equal
		if !originalPoint.Equal(parsedPoint) {
			t.Error("parsed point should equal original")
		}
	})

	t.Run("ScalarMult", func(t *testing.T) {
		// Generate test data
		scalar1, _ := curve.GenerateScalar()
		scalar2, _ := curve.GenerateScalar()

		point := curve.ScalarBaseMult(scalar1)
		result := curve.ScalarMult(point, scalar2)

		if result == nil {
			t.Fatal("ScalarMult returned nil")
		}

		if err := curve.ValidatePoint(result); err != nil {
			t.Errorf("invalid result point: %v", err)
		}
	})

	t.Run("Add", func(t *testing.T) {
		// Generate test points
		s1, _ := curve.GenerateScalar()
		s2, _ := curve.GenerateScalar()

		p1 := curve.ScalarBaseMult(s1)
		p2 := curve.ScalarBaseMult(s2)

		sum := curve.Add(p1, p2)

		if sum == nil {
			t.Fatal("Add returned nil")
		}

		if err := curve.ValidatePoint(sum); err != nil {
			t.Errorf("invalid sum point: %v", err)
		}
	})

	t.Run("InvalidPoint", func(t *testing.T) {
		// Test with invalid point data
		invalidPoint := make([]byte, 33)
		// All zeros is invalid
		_, err := curve.ParsePoint(invalidPoint)
		if err == nil {
			t.Error("should reject invalid point")
		}

		// Test with wrong length
		_, err = curve.ParsePoint([]byte{0x02, 0x03})
		if err == nil {
			t.Error("should reject point with wrong length")
		}
	})
}

func TestSecp256k1KnownValues(t *testing.T) {
	curve := NewSecp256k1()

	// Test with known secp256k1 values
	// Private key: 1
	privateKeyBytes := make([]byte, 32)
	privateKeyBytes[31] = 1

	privateKey, err := curve.ParseScalar(privateKeyBytes)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}

	// Public key should be the generator point
	publicKey := curve.ScalarBaseMult(privateKey)

	// Expected compressed public key for secp256k1 generator
	expectedPubKey := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	expectedBytes, _ := hex.DecodeString(expectedPubKey)

	actualBytes := publicKey.Bytes()

	if hex.EncodeToString(actualBytes) != expectedPubKey {
		t.Errorf("expected public key %s, got %s", expectedPubKey, hex.EncodeToString(actualBytes))
	}

	// Verify point parsing
	parsedPoint, err := curve.ParsePoint(expectedBytes)
	if err != nil {
		t.Fatalf("failed to parse expected point: %v", err)
	}

	if !publicKey.Equal(parsedPoint) {
		t.Error("parsed point should equal computed point")
	}
}