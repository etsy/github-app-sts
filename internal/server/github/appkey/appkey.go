package appkey

import "context"

type AppKey interface {
	ClientID() string
	SignRS256(ctx context.Context, digest [32]byte) (signature []byte, err error)
}
