package envelope

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// ECDSAPublicKeyFromJWTX5C returns the P-256 public key from the JWT header x5c leaf.
func ECDSAPublicKeyFromJWTX5C(token *jwt.Token) (*ecdsa.PublicKey, error) {
	if token == nil {
		return nil, fmt.Errorf("jwt token is nil")
	}
	raw, ok := token.Header["x5c"]
	if !ok {
		return nil, fmt.Errorf("jwt missing x5c header")
	}
	certs, ok := raw.([]any)
	if !ok || len(certs) == 0 {
		return nil, fmt.Errorf("x5c header is empty")
	}
	leafB64, ok := certs[0].(string)
	if !ok || strings.TrimSpace(leafB64) == "" {
		return nil, fmt.Errorf("x5c leaf certificate is invalid")
	}
	der, err := base64.StdEncoding.DecodeString(leafB64)
	if err != nil {
		return nil, fmt.Errorf("decode x5c leaf certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse x5c leaf certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("x5c leaf certificate public key is not ECDSA")
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("x5c leaf certificate is not P-256")
	}
	return pub, nil
}
