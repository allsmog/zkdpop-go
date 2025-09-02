package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// jwkToPublicKey converts a JWK to a Go public key for JWT verification
func jwkToPublicKey(jwk *JWK) (interface{}, error) {
	switch jwk.Kty {
	case "EC":
		return ecJWKToPublicKey(jwk)
	case "RSA":
		return rsaJWKToPublicKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

// ecJWKToPublicKey converts an EC JWK to an ECDSA public key
func ecJWKToPublicKey(jwk *JWK) (*ecdsa.PublicKey, error) {
	// Get the curve
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	case "secp256k1":
		// Note: Go's standard library doesn't include secp256k1
		// For production, you'd need to use a library like btcec
		return nil, fmt.Errorf("secp256k1 not supported in standard library")
	default:
		return nil, fmt.Errorf("unsupported curve: %s", jwk.Crv)
	}

	// Decode coordinates
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x coordinate: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y coordinate: %w", err)
	}

	// Create big integers
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Verify point is on curve
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("point is not on curve")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// rsaJWKToPublicKey converts an RSA JWK to an RSA public key
func rsaJWKToPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	// Decode modulus
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode exponent
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Create big integers
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	// Validate exponent fits in int
	if !e.IsInt64() || e.Int64() > int64(^uint(0)>>1) {
		return nil, fmt.Errorf("exponent too large")
	}

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// PublicKeyToJWK converts a Go public key to a JWK
func PublicKeyToJWK(publicKey interface{}) (*JWK, error) {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		return ecPublicKeyToJWK(key)
	case *rsa.PublicKey:
		return rsaPublicKeyToJWK(key)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", publicKey)
	}
}

// ecPublicKeyToJWK converts an ECDSA public key to a JWK
func ecPublicKeyToJWK(key *ecdsa.PublicKey) (*JWK, error) {
	var crv string
	var keySize int

	switch key.Curve {
	case elliptic.P256():
		crv = "P-256"
		keySize = 32
	case elliptic.P384():
		crv = "P-384"
		keySize = 48
	case elliptic.P521():
		crv = "P-521"
		keySize = 66
	default:
		return nil, fmt.Errorf("unsupported curve")
	}

	// Convert coordinates to fixed-length byte arrays
	xBytes := key.X.Bytes()
	yBytes := key.Y.Bytes()

	// Pad with leading zeros if necessary
	if len(xBytes) < keySize {
		padded := make([]byte, keySize)
		copy(padded[keySize-len(xBytes):], xBytes)
		xBytes = padded
	}

	if len(yBytes) < keySize {
		padded := make([]byte, keySize)
		copy(padded[keySize-len(yBytes):], yBytes)
		yBytes = padded
	}

	return &JWK{
		Kty: "EC",
		Crv: crv,
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
		Use: "sig",
	}, nil
}

// rsaPublicKeyToJWK converts an RSA public key to a JWK
func rsaPublicKeyToJWK(key *rsa.PublicKey) (*JWK, error) {
	// Convert modulus and exponent to bytes
	nBytes := key.N.Bytes()
	
	// Convert exponent to bytes
	e := big.NewInt(int64(key.E))
	eBytes := e.Bytes()

	return &JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
		Use: "sig",
	}, nil
}