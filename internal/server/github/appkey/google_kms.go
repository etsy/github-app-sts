package appkey

import (
	"context"
	"fmt"

	cloudkms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

var _ AppKey = (*GoogleKMS)(nil)

type GoogleKMS struct {
	clientID   string
	resourceID string

	client *cloudkms.KeyManagementClient
}

func NewGoogleKMS(ctx context.Context, clientID string, resourceID string) (*GoogleKMS, error) {
	client, err := cloudkms.NewKeyManagementClient(ctx)

	if err != nil {
		return nil, fmt.Errorf("could not construct KMS client: %w", err)
	}

	// Use GetPublicKey instead of GetCryptoKeyVersion so that the service account
	// only needs roles/cloudkms.signerVerifier (which includes viewPublicKey)
	// rather than the broader roles/cloudkms.viewer (which includes cryptoKeyVersions.get).
	publicKey, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: resourceID,
	})

	if err != nil {
		return nil, fmt.Errorf("could not fetch KMS public key: %w", err)
	}

	if publicKey.Algorithm != kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256 &&
		publicKey.Algorithm != kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256 &&
		publicKey.Algorithm != kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256 {

		return nil, fmt.Errorf("KMS key must be of type RSA_SIGN_PKCS1_*_SHA256")
	}

	return &GoogleKMS{clientID, resourceID, client}, nil
}

func (s *GoogleKMS) ClientID() string {
	return s.clientID
}

func (s *GoogleKMS) SignRS256(
	ctx context.Context,
	digest [32]byte,
) ([]byte, error) {
	signRequest := &kmspb.AsymmetricSignRequest{
		Name:   s.resourceID,
		Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest[:]}},
	}

	signResponse, err := s.client.AsymmetricSign(ctx, signRequest)

	if err != nil {
		return nil, fmt.Errorf("SignRS256(): %w", err)
	}

	return signResponse.Signature, nil
}
