package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

// GenerateES256KeyPair generates a new ECDSA P-256 key pair
func GenerateES256KeyPair() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	return privateKey, nil
}

// GenerateRSAKeyPair generates a new RSA key pair
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	return privateKey, nil
}

// SavePrivateKeyPEM saves a private key to a PEM file
func SavePrivateKeyPEM(privateKey interface{}, filename string) error {
	var keyBytes []byte
	var keyType string

	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		var err error
		keyBytes, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return fmt.Errorf("failed to marshal ECDSA private key: %w", err)
		}
		keyType = "EC PRIVATE KEY"

	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
		keyType = "RSA PRIVATE KEY"

	default:
		return fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	block := &pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("failed to encode PEM: %w", err)
	}

	return nil
}

// LoadPrivateKeyPEM loads a private key from a PEM file
func LoadPrivateKeyPEM(filename string) (interface{}, error) {
	keyBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

// KeyConfig represents key configuration
type KeyConfig struct {
	Type   string `json:"type"`   // "ecdsa" or "rsa"
	KeyID  string `json:"kid"`    // Key ID
	Issuer string `json:"issuer"` // Issuer identifier
}

// SaveKeyConfig saves key configuration to a JSON file
func SaveKeyConfig(config *KeyConfig, filename string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// LoadKeyConfig loads key configuration from a JSON file
func LoadKeyConfig(filename string) (*KeyConfig, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config KeyConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

// NewES256SignerFromFile creates an ES256 signer from PEM and config files
func NewES256SignerFromFile(keyFile, configFile string) (*ES256Signer, error) {
	// Load private key
	privateKeyRaw, err := LoadPrivateKeyPEM(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	privateKey, ok := privateKeyRaw.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected ECDSA private key, got %T", privateKeyRaw)
	}

	// Load configuration
	config, err := LoadKeyConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return NewES256Signer(privateKey, config.KeyID, config.Issuer)
}

// GenerateKeyPairFiles generates a key pair and saves it to files
func GenerateKeyPairFiles(keyType, keyID, issuer, keyFile, configFile string) error {
	var privateKey interface{}
	var err error

	switch keyType {
	case "ecdsa":
		privateKey, err = GenerateES256KeyPair()
	case "rsa":
		privateKey, err = GenerateRSAKeyPair(2048)
	default:
		return fmt.Errorf("unsupported key type: %s", keyType)
	}

	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Save private key
	if err := SavePrivateKeyPEM(privateKey, keyFile); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Save configuration
	config := &KeyConfig{
		Type:   keyType,
		KeyID:  keyID,
		Issuer: issuer,
	}

	if err := SaveKeyConfig(config, configFile); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	return nil
}