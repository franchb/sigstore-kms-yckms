package yckms

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	AlgorithmECDSANISTP256SHA256  = "ecdsa-nist-p256-sha256"
	AlgorithmECDSANISTP384SHA384  = "ecdsa-nist-p384-sha384"
	AlgorithmECDSANISTP521SHA512  = "ecdsa-nist-p521-sha512"
	AlgorithmRSA2048SignPSSSHA256 = "rsa-2048-pss-sha256"
	AlgorithmRSA2048SignPSSSHA384 = "rsa-2048-pss-sha384"
	AlgorithmRSA2048SignPSSSHA512 = "rsa-2048-pss-sha512"
	AlgorithmRSA3072SignPSSSHA256 = "rsa-3072-pss-sha256"
	AlgorithmRSA3072SignPSSSHA384 = "rsa-3072-pss-sha384"
	AlgorithmRSA3072SignPSSSHA512 = "rsa-3072-pss-sha512"
	AlgorithmRSA4096SignPSSSHA256 = "rsa-4096-pss-sha256"
	AlgorithmRSA4096SignPSSSHA384 = "rsa-4096-pss-sha384"
	AlgorithmRSA4096SignPSSSHA512 = "rsa-4096-pss-sha512"
)

var (
	errUninitializedSignerVerifier = errors.New("yckms signer verifier is not initialized")

	ycSupportedHashFuncs = []crypto.Hash{
		crypto.SHA256,
		crypto.SHA512,
		crypto.SHA384,
	}
)

type SignerVerifier struct {
	client *ycKmsClient
}

func LoadSignerVerifier(ctx context.Context, resourceID string) (*SignerVerifier, error) {
	client, err := newYcKmsClient(ctx, resourceID)
	if err != nil {
		return nil, err
	}

	return &SignerVerifier{client: client}, nil
}

func (y *SignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	if y == nil || y.client == nil {
		return nil, errUninitializedSignerVerifier
	}

	ctx := context.Background()
	defaultHash, err := y.client.getHashFunc(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch default hash function: %w", err)
	}

	var digest []byte
	var signerOpts crypto.SignerOpts = defaultHash
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	hashFunc := signerOpts.HashFunc()
	if len(digest) == 0 {
		digest, hashFunc, err = signature.ComputeDigestForSigning(message, hashFunc, ycSupportedHashFuncs, opts...)
		if err != nil {
			return nil, err
		}
	}

	return y.client.sign(ctx, digest, hashFunc)
}

func (y *SignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	if y == nil || y.client == nil {
		return nil, errUninitializedSignerVerifier
	}

	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}

	signatureKey, err := y.client.getSK(ctx)
	if err != nil {
		return nil, err
	}

	return signatureKey.Verifier.PublicKey(opts...)
}

func (y *SignerVerifier) VerifySignature(sig, message io.Reader, opts ...signature.VerifyOption) error {
	if y == nil || y.client == nil {
		return errUninitializedSignerVerifier
	}

	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}

	return y.client.verify(ctx, sig, message, opts...)
}

func (y *SignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	if y == nil || y.client == nil {
		return nil, errUninitializedSignerVerifier
	}

	return y.client.createKey(ctx, algorithm)
}

type cryptoSignerWrapper struct {
	ctx      context.Context //nolint:containedctx // required by crypto.Signer Public/Sign API bridge
	sv       *SignerVerifier
	errFunc  func(error)
	hashFunc crypto.Hash
}

func (c cryptoSignerWrapper) Public() crypto.PublicKey {
	publicKey, err := c.sv.PublicKey(options.WithContext(c.ctx))
	if err != nil && c.errFunc != nil {
		c.errFunc(err)
	}

	return publicKey
}

func (c cryptoSignerWrapper) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashFunc := c.hashFunc
	if opts != nil {
		hashFunc = opts.HashFunc()
	}

	signOptions := []signature.SignOption{
		options.WithContext(c.ctx),
		options.WithDigest(digest),
		options.WithCryptoSignerOpts(hashFunc),
	}

	return c.sv.SignMessage(nil, signOptions...)
}

func (y *SignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	if y == nil || y.client == nil {
		return nil, nil, errUninitializedSignerVerifier
	}

	defaultHash, err := y.client.getHashFunc(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch default hash function: %w", err)
	}

	return &cryptoSignerWrapper{
		ctx:      ctx,
		sv:       y,
		hashFunc: defaultHash,
		errFunc:  errFunc,
	}, defaultHash, nil
}

func (*SignerVerifier) SupportedAlgorithms() []string {
	result := make([]string, 0, len(algorithmMap))
	for algorithm := range algorithmMap {
		result = append(result, algorithm)
	}

	return result
}

func (*SignerVerifier) DefaultAlgorithm() string {
	return AlgorithmECDSANISTP256SHA256
}

func defaultHashFunc() crypto.Hash {
	return crypto.SHA256
}
