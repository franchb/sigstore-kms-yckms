//
// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	// AlgorithmECDSANISTP256SHA256 identifies ECDSA NIST P-256 with SHA-256.
	AlgorithmECDSANISTP256SHA256 = "ecdsa-nist-p256-sha256"
	// AlgorithmECDSANISTP384SHA384 identifies ECDSA NIST P-384 with SHA-384.
	AlgorithmECDSANISTP384SHA384 = "ecdsa-nist-p384-sha384"
	// AlgorithmECDSANISTP521SHA512 identifies ECDSA NIST P-521 with SHA-512.
	AlgorithmECDSANISTP521SHA512 = "ecdsa-nist-p521-sha512"
	// AlgorithmRSA2048SignPSSSHA256 identifies RSA-2048 PSS with SHA-256.
	AlgorithmRSA2048SignPSSSHA256 = "rsa-2048-pss-sha256"
	// AlgorithmRSA2048SignPSSSHA384 identifies RSA-2048 PSS with SHA-384.
	AlgorithmRSA2048SignPSSSHA384 = "rsa-2048-pss-sha384"
	// AlgorithmRSA2048SignPSSSHA512 identifies RSA-2048 PSS with SHA-512.
	AlgorithmRSA2048SignPSSSHA512 = "rsa-2048-pss-sha512"
	// AlgorithmRSA3072SignPSSSHA256 identifies RSA-3072 PSS with SHA-256.
	AlgorithmRSA3072SignPSSSHA256 = "rsa-3072-pss-sha256"
	// AlgorithmRSA3072SignPSSSHA384 identifies RSA-3072 PSS with SHA-384.
	AlgorithmRSA3072SignPSSSHA384 = "rsa-3072-pss-sha384"
	// AlgorithmRSA3072SignPSSSHA512 identifies RSA-3072 PSS with SHA-512.
	AlgorithmRSA3072SignPSSSHA512 = "rsa-3072-pss-sha512"
	// AlgorithmRSA4096SignPSSSHA256 identifies RSA-4096 PSS with SHA-256.
	AlgorithmRSA4096SignPSSSHA256 = "rsa-4096-pss-sha256"
	// AlgorithmRSA4096SignPSSSHA384 identifies RSA-4096 PSS with SHA-384.
	AlgorithmRSA4096SignPSSSHA384 = "rsa-4096-pss-sha384"
	// AlgorithmRSA4096SignPSSSHA512 identifies RSA-4096 PSS with SHA-512.
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

// SignerVerifier signs messages with Yandex Cloud KMS and verifies signatures locally.
type SignerVerifier struct {
	client *ycKmsClient
}

// LoadSignerVerifier creates a SignerVerifier for a provider-stripped yckms resource ID.
func LoadSignerVerifier(ctx context.Context, resourceID string) (*SignerVerifier, error) {
	client, err := newYcKmsClient(ctx, resourceID)
	if err != nil {
		return nil, err
	}

	return &SignerVerifier{client: client}, nil
}

// SignMessage signs message with Yandex Cloud KMS, computing a digest when one is not provided.
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

// PublicKey returns the public key used to verify signatures from this SignerVerifier.
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

// VerifySignature verifies a signature against message using the KMS key's public key.
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

// CreateKey creates a new Yandex Cloud KMS asymmetric signature key.
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

// CryptoSigner returns a crypto.Signer adapter for APIs that use standard Go signing interfaces.
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

// SupportedAlgorithms returns the Yandex Cloud KMS asymmetric signing algorithms supported by this package.
func (*SignerVerifier) SupportedAlgorithms() []string {
	result := make([]string, 0, len(algorithmMap))
	for algorithm := range algorithmMap {
		result = append(result, algorithm)
	}

	return result
}

// DefaultAlgorithm returns the default Yandex Cloud KMS asymmetric signing algorithm.
func (*SignerVerifier) DefaultAlgorithm() string {
	return AlgorithmECDSANISTP256SHA256
}
