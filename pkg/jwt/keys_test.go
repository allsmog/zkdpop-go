package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"os"
	"testing"
)

func TestGenerateES256KeyPair(t *testing.T) {
	privateKey, err := GenerateES256KeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	if privateKey.Curve != elliptic.P256() {
		t.Error("expected P-256 curve")
	}

	// Verify key is valid by signing something
	if privateKey.D == nil || privateKey.X == nil || privateKey.Y == nil {
		t.Error("key components should not be nil")
	}

	// Verify point is on curve
	if !privateKey.Curve.IsOnCurve(privateKey.X, privateKey.Y) {
		t.Error("public key should be on curve")
	}
}

func TestGenerateRSAKeyPair(t *testing.T) {
	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key pair: %v", err)
	}

	if privateKey.Size() != 2048/8 {
		t.Errorf("expected 2048-bit key, got %d-bit", privateKey.Size()*8)
	}

	// Verify key components
	if privateKey.N == nil || privateKey.D == nil {
		t.Error("key components should not be nil")
	}

	if privateKey.E != 65537 {
		t.Errorf("expected exponent 65537, got %d", privateKey.E)
	}
}

func TestSaveLoadPrivateKeyPEM(t *testing.T) {
	tempFile := "/tmp/test-private-key.pem"
	defer os.Remove(tempFile)

	t.Run("ECDSA", func(t *testing.T) {
		// Generate key
		originalKey, err := GenerateES256KeyPair()
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		// Save key
		err = SavePrivateKeyPEM(originalKey, tempFile)
		if err != nil {
			t.Fatalf("failed to save key: %v", err)
		}

		// Load key
		loadedKey, err := LoadPrivateKeyPEM(tempFile)
		if err != nil {
			t.Fatalf("failed to load key: %v", err)
		}

		// Verify it's an ECDSA key
		ecdsaKey, ok := loadedKey.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatal("loaded key should be ECDSA")
		}

		// Verify keys match
		if originalKey.D.Cmp(ecdsaKey.D) != 0 {
			t.Error("private key values should match")
		}

		if originalKey.X.Cmp(ecdsaKey.X) != 0 || originalKey.Y.Cmp(ecdsaKey.Y) != 0 {
			t.Error("public key values should match")
		}
	})

	t.Run("RSA", func(t *testing.T) {
		// Generate key
		originalKey, err := GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		// Save key
		err = SavePrivateKeyPEM(originalKey, tempFile)
		if err != nil {
			t.Fatalf("failed to save key: %v", err)
		}

		// Load key
		loadedKey, err := LoadPrivateKeyPEM(tempFile)
		if err != nil {
			t.Fatalf("failed to load key: %v", err)
		}

		// Verify it's an RSA key
		rsaKey, ok := loadedKey.(*rsa.PrivateKey)
		if !ok {
			t.Fatal("loaded key should be RSA")
		}

		// Verify keys match
		if originalKey.N.Cmp(rsaKey.N) != 0 {
			t.Error("modulus should match")
		}

		if originalKey.E != rsaKey.E {
			t.Error("exponent should match")
		}

		if originalKey.D.Cmp(rsaKey.D) != 0 {
			t.Error("private exponent should match")
		}
	})
}

func TestSaveLoadKeyConfig(t *testing.T) {
	tempFile := "/tmp/test-config.json"
	defer os.Remove(tempFile)

	originalConfig := &KeyConfig{
		Type:   "ecdsa",
		KeyID:  "test-key-id",
		Issuer: "https://test.issuer.com",
	}

	// Save config
	err := SaveKeyConfig(originalConfig, tempFile)
	if err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	// Load config
	loadedConfig, err := LoadKeyConfig(tempFile)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Verify configs match
	if originalConfig.Type != loadedConfig.Type {
		t.Errorf("type mismatch: %s vs %s", originalConfig.Type, loadedConfig.Type)
	}

	if originalConfig.KeyID != loadedConfig.KeyID {
		t.Errorf("key ID mismatch: %s vs %s", originalConfig.KeyID, loadedConfig.KeyID)
	}

	if originalConfig.Issuer != loadedConfig.Issuer {
		t.Errorf("issuer mismatch: %s vs %s", originalConfig.Issuer, loadedConfig.Issuer)
	}
}

func TestGenerateKeyPairFiles(t *testing.T) {
	keyFile := "/tmp/test-key.pem"
	configFile := "/tmp/test-config.json"
	defer os.Remove(keyFile)
	defer os.Remove(configFile)

	err := GenerateKeyPairFiles("ecdsa", "test-key", "https://test.issuer.com", keyFile, configFile)
	if err != nil {
		t.Fatalf("failed to generate key pair files: %v", err)
	}

	// Verify key file exists and is valid
	privateKey, err := LoadPrivateKeyPEM(keyFile)
	if err != nil {
		t.Fatalf("failed to load generated key: %v", err)
	}

	_, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Error("generated key should be ECDSA")
	}

	// Verify config file exists and is valid
	config, err := LoadKeyConfig(configFile)
	if err != nil {
		t.Fatalf("failed to load generated config: %v", err)
	}

	if config.Type != "ecdsa" {
		t.Errorf("wrong type: %s", config.Type)
	}

	if config.KeyID != "test-key" {
		t.Errorf("wrong key ID: %s", config.KeyID)
	}

	if config.Issuer != "https://test.issuer.com" {
		t.Errorf("wrong issuer: %s", config.Issuer)
	}
}

func TestNewES256SignerFromFile(t *testing.T) {
	keyFile := "/tmp/test-signer-key.pem"
	configFile := "/tmp/test-signer-config.json"
	defer os.Remove(keyFile)
	defer os.Remove(configFile)

	// Generate files
	err := GenerateKeyPairFiles("ecdsa", "signer-test-key", "https://signer.test.com", keyFile, configFile)
	if err != nil {
		t.Fatalf("failed to generate files: %v", err)
	}

	// Create signer from files
	signer, err := NewES256SignerFromFile(keyFile, configFile)
	if err != nil {
		t.Fatalf("failed to create signer from files: %v", err)
	}

	// Verify signer properties
	if signer.Algorithm() != "ES256" {
		t.Errorf("wrong algorithm: %s", signer.Algorithm())
	}

	// Verify JWKS contains the key
	jwks := signer.JWKS()
	if jwks.Len() != 1 {
		t.Errorf("expected 1 key, got %d", jwks.Len())
	}

	// Test signing
	claims := map[string]interface{}{
		"test": "claim",
	}

	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	if token == "" {
		t.Error("token should not be empty")
	}
}

func TestInvalidKeyTypes(t *testing.T) {
	t.Run("SaveUnsupportedKey", func(t *testing.T) {
		err := SavePrivateKeyPEM("not-a-key", "/tmp/invalid")
		if err == nil {
			t.Error("should fail with unsupported key type")
		}
	})

	t.Run("LoadNonexistentFile", func(t *testing.T) {
		_, err := LoadPrivateKeyPEM("/tmp/nonexistent-file.pem")
		if err == nil {
			t.Error("should fail when file doesn't exist")
		}
	})

	t.Run("LoadInvalidJSON", func(t *testing.T) {
		tempFile := "/tmp/invalid.json"
		defer os.Remove(tempFile)

		// Write invalid JSON
		err := os.WriteFile(tempFile, []byte("invalid json"), 0644)
		if err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		_, err = LoadKeyConfig(tempFile)
		if err == nil {
			t.Error("should fail with invalid JSON")
		}
	})

	t.Run("GenerateUnsupportedKeyType", func(t *testing.T) {
		err := GenerateKeyPairFiles("unsupported", "test", "test", "/tmp/test", "/tmp/test")
		if err == nil {
			t.Error("should fail with unsupported key type")
		}
	})
}