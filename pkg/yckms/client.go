//
// Copyright 2023 The Sigstore Authors.
//
// SPDX-License-Identifier: Apache-2.0
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
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	asymkms "github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1/asymmetricsignature"
	ycsdk "github.com/yandex-cloud/go-sdk"
	"google.golang.org/grpc"
)

const cacheKey = "sign_key"

// algorithmMap maps this package's algorithm names to Yandex Cloud KMS algorithms.
func algorithmMap() map[string]asymkms.AsymmetricSignatureAlgorithm {
	return map[string]asymkms.AsymmetricSignatureAlgorithm{
		AlgorithmECDSANISTP256SHA256:  asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P256_SHA_256,
		AlgorithmECDSANISTP384SHA384:  asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P384_SHA_384,
		AlgorithmECDSANISTP521SHA512:  asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P521_SHA_512,
		AlgorithmRSA2048SignPSSSHA256: asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_256,
		AlgorithmRSA2048SignPSSSHA384: asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_384,
		AlgorithmRSA2048SignPSSSHA512: asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_512,
		AlgorithmRSA3072SignPSSSHA256: asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_256,
		AlgorithmRSA3072SignPSSSHA384: asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_384,
		AlgorithmRSA3072SignPSSSHA512: asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_512,
		AlgorithmRSA4096SignPSSSHA256: asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_256,
		AlgorithmRSA4096SignPSSSHA384: asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_384,
		AlgorithmRSA4096SignPSSSHA512: asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_512,
	}
}

type ycKmsClient struct {
	client    *ycsdk.SDK
	skCache   *ttlcache.Cache[string, ycSignatureKey]
	endpoint  string
	refString string
	folderID  string
	keyID     string
	keyName   string
}

type ycSignatureKey struct {
	SignatureKey *asymkms.AsymmetricSignatureKey
	Verifier     signature.Verifier
	HashFunc     crypto.Hash
}

func newYcKmsClient(ctx context.Context, resourceID string, opts ...grpc.DialOption) (*ycKmsClient, error) {
	if err := ValidReference(resourceID); err != nil {
		return nil, err
	}

	y := &ycKmsClient{refString: resourceID}

	var err error

	y.endpoint, y.keyID, y.folderID, y.keyName, err = ParseReference(resourceID)
	if err != nil {
		return nil, err
	}

	creds, err := credentials(ctx)
	if err != nil {
		return nil, err
	}

	conf := ycsdk.Config{Credentials: creds}
	if y.endpoint != "" {
		conf.Endpoint = y.endpoint
	}

	y.client, err = ycsdk.Build(ctx, conf, opts...)
	if err != nil {
		return nil, fmt.Errorf("new yc kms client: %w", err)
	}

	y.skCache = ttlcache.New[string, ycSignatureKey](
		ttlcache.WithDisableTouchOnHit[string, ycSignatureKey](),
	)

	return y, nil
}

// verifierForAlgorithm returns a local verifier and digest algorithm for a KMS signature algorithm.
func verifierForAlgorithm(
	alg asymkms.AsymmetricSignatureAlgorithm,
	pubKey crypto.PublicKey,
) (signature.Verifier, crypto.Hash, error) {
	var hashFunc crypto.Hash

	switch alg {
	case asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_256,
		asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_256,
		asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_256:
		hashFunc = crypto.SHA256
	case asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_384,
		asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_384,
		asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_384:
		hashFunc = crypto.SHA384
	case asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_512,
		asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_512,
		asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_512:
		hashFunc = crypto.SHA512
	case asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P256_SHA_256:
		return ecdsaVerifier(pubKey, crypto.SHA256)
	case asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P384_SHA_384:
		return ecdsaVerifier(pubKey, crypto.SHA384)
	case asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P521_SHA_512:
		return ecdsaVerifier(pubKey, crypto.SHA512)
	case asymkms.AsymmetricSignatureAlgorithm_ASYMMETRIC_SIGNATURE_ALGORITHM_UNSPECIFIED,
		asymkms.AsymmetricSignatureAlgorithm_ECDSA_SECP256_K1_SHA_256:
		return nil, 0, ErrUnsupportedAlgorithm
	default:
		return nil, 0, ErrUnsupportedAlgorithm
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, 0, ErrPublicKeyNotRSA
	}

	verifier, err := signature.LoadRSAPSSVerifier(rsaPubKey, hashFunc, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("initializing internal RSA-PSS verifier: %w", err)
	}

	return verifier, hashFunc, nil
}

// ecdsaVerifier returns a local ECDSA verifier for pubKey at the given digest algorithm.
func ecdsaVerifier(pubKey crypto.PublicKey, hashFunc crypto.Hash) (signature.Verifier, crypto.Hash, error) {
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, 0, ErrPublicKeyNotECDSA
	}

	verifier, err := signature.LoadECDSAVerifier(ecdsaPubKey, hashFunc)
	if err != nil {
		return nil, 0, fmt.Errorf("initializing internal ECDSA verifier: %w", err)
	}

	return verifier, hashFunc, nil
}

func (y *ycKmsClient) getYcSignatureKey(ctx context.Context) (*ycSignatureKey, error) {
	getRequest := &asymkms.GetAsymmetricSignatureKeyRequest{KeyId: y.keyID}

	asymKey, err := y.client.KMSAsymmetricSignature().AsymmetricSignatureKey().Get(ctx, getRequest)
	if err != nil {
		return nil, fmt.Errorf("fetching yckms signature key %q: %w", y.keyID, err)
	}

	pubKey, err := y.fetchPublicKey(ctx)
	if err != nil {
		return nil, err
	}

	verifier, hashFunc, err := verifierForAlgorithm(asymKey.GetSignatureAlgorithm(), pubKey)
	if err != nil {
		return nil, err
	}

	return &ycSignatureKey{
		SignatureKey: asymKey,
		Verifier:     verifier,
		HashFunc:     hashFunc,
	}, nil
}

func (y *ycKmsClient) getHashFunc(ctx context.Context) (crypto.Hash, error) {
	signatureKey, err := y.getSK(ctx)
	if err != nil {
		return 0, err
	}

	return signatureKey.HashFunc, nil
}

// signatureKeyTTL bounds how long a fetched KMS signature key is cached.
const signatureKeyTTL = 5 * time.Minute

func (y *ycKmsClient) getSK(ctx context.Context) (*ycSignatureKey, error) {
	var loaderErr error

	loader := ttlcache.LoaderFunc[string, ycSignatureKey](
		func(cache *ttlcache.Cache[string, ycSignatureKey], key string) *ttlcache.Item[string, ycSignatureKey] {
			signatureKey, err := y.getYcSignatureKey(ctx)
			if err != nil {
				loaderErr = err

				return nil
			}

			return cache.Set(key, *signatureKey, signatureKeyTTL)
		},
	)

	item := y.skCache.Get(cacheKey, ttlcache.WithLoader[string, ycSignatureKey](loader))

	if loaderErr != nil {
		return nil, loaderErr
	}

	if item == nil {
		return nil, errSignatureKeyCacheEmpty
	}

	signatureKey := item.Value()

	return &signatureKey, nil
}

func (y *ycKmsClient) createKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	if y.folderID == "" || y.keyName == "" {
		return nil, ErrCreateKeyReference
	}

	signatureAlgorithm, ok := algorithmMap()[algorithm]
	if !ok {
		return nil, ErrUnknownAlgorithm
	}

	createKeyRequest := &asymkms.CreateAsymmetricSignatureKeyRequest{
		SignatureAlgorithm: signatureAlgorithm,
		FolderId:           y.folderID,
		Name:               y.keyName,
		Description:        "Created by sigstore",
		Labels:             nil,
		DeletionProtection: false,
	}

	createResponse, createErr := y.client.KMSAsymmetricSignature().
		AsymmetricSignatureKey().Create(ctx, createKeyRequest)

	op, err := y.client.WrapOperation(createResponse, createErr)
	if err != nil {
		return nil, fmt.Errorf("yckms key create error: %w", err)
	}

	if err := op.Wait(ctx); err != nil {
		return nil, fmt.Errorf("yckms key create error: %w", err)
	}

	resp, err := op.Response()
	if err != nil {
		return nil, fmt.Errorf("yckms key create error: %w", err)
	}

	key, ok := resp.(*asymkms.AsymmetricSignatureKey)
	if !ok {
		return nil, errUnexpectedCreateKeyResponse
	}

	getPubKeyRequest := &asymkms.AsymmetricGetPublicKeyRequest{KeyId: key.GetId()}

	pubKey, err := y.client.KMSAsymmetricSignatureCrypto().AsymmetricSignatureCrypto().GetPublicKey(ctx, getPubKeyRequest)
	if err != nil {
		return nil, fmt.Errorf("fetching public key for created yckms key: %w", err)
	}

	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(pubKey.GetPublicKey()))
	if err != nil {
		return nil, fmt.Errorf("parsing PEM public key for created yckms key: %w", err)
	}

	return publicKey, nil
}

func (y *ycKmsClient) verify(ctx context.Context, sig, message io.Reader, opts ...signature.VerifyOption) error {
	signatureKey, err := y.getSK(ctx)
	if err != nil {
		return err
	}

	if err := signatureKey.Verifier.VerifySignature(sig, message, opts...); err != nil {
		return fmt.Errorf("verifying yckms signature: %w", err)
	}

	return nil
}

func (y *ycKmsClient) sign(ctx context.Context, digest []byte, _ crypto.Hash) ([]byte, error) {
	signHashRequest := &asymkms.AsymmetricSignHashRequest{
		KeyId: y.keyID,
		Hash:  digest,
	}

	signResponse, err := y.client.KMSAsymmetricSignatureCrypto().AsymmetricSignatureCrypto().SignHash(ctx, signHashRequest)
	if err != nil {
		return nil, fmt.Errorf("calling YC KMS AsymmetricSignatureCrypto.SignHash: %w", err)
	}

	return signResponse.GetSignature(), nil
}

func (y *ycKmsClient) fetchPublicKey(ctx context.Context) (crypto.PublicKey, error) {
	getPubKeyRequest := &asymkms.AsymmetricGetPublicKeyRequest{KeyId: y.keyID}

	pubKey, err := y.client.KMSAsymmetricSignatureCrypto().AsymmetricSignatureCrypto().GetPublicKey(ctx, getPubKeyRequest)
	if err != nil {
		return nil, fmt.Errorf("fetching yckms public key for key %q: %w", y.keyID, err)
	}

	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(pubKey.GetPublicKey()))
	if err != nil {
		return nil, fmt.Errorf("parsing yckms PEM public key: %w", err)
	}

	return publicKey, nil
}
