package appkey

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

var _ AppKey = (*RSA)(nil)

type RSA struct {
	clientID   string
	privateKey *rsa.PrivateKey
}

func NewRSAFromFile(clientID string, path string) (*RSA, error) {
	fileContents, err := os.ReadFile(path)

	if err != nil {
		return nil, fmt.Errorf("could not read private key: %w", err)
	}

	return NewRSA(clientID, fileContents)
}

func NewRSA(clientID string, fileContents []byte) (*RSA, error) {
	block, _ := pem.Decode(fileContents)

	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)

	if err != nil {
		return nil, fmt.Errorf("could not parse private key: %w", err)
	}

	return &RSA{clientID, privateKey}, nil
}

func (s *RSA) ClientID() string {
	return s.clientID
}

func (s *RSA) SignRS256(
	_ context.Context,
	digest [32]byte,
) ([]byte, error) {
	return rsa.SignPKCS1v15(nil, s.privateKey, crypto.SHA256, digest[:])
}
