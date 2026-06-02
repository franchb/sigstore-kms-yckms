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
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
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

var algorithmMap = map[string]asymkms.AsymmetricSignatureAlgorithm{
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

func (y *ycKmsClient) getYcSignatureKey(ctx context.Context) (*ycSignatureKey, error) {
	getRequest := &asymkms.GetAsymmetricSignatureKeyRequest{KeyId: y.keyID}

	asymKey, err := y.client.KMSAsymmetricSignature().AsymmetricSignatureKey().Get(ctx, getRequest)
	if err != nil {
		return nil, err
	}

	pubKey, err := y.fetchPublicKey(ctx)
	if err != nil {
		return nil, err
	}

	signatureKey := ycSignatureKey{SignatureKey: asymKey}
	switch asymKey.SignatureAlgorithm {
	case asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_256,
		asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_256,
		asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_256:
		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("public key is not RSA")
		}

		signatureKey.Verifier, err = signature.LoadRSAPSSVerifier(rsaPubKey, crypto.SHA256, nil)
		signatureKey.HashFunc = crypto.SHA256
	case asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_384,
		asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_384,
		asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_384:
		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("public key is not RSA")
		}

		signatureKey.Verifier, err = signature.LoadRSAPSSVerifier(rsaPubKey, crypto.SHA384, nil)
		signatureKey.HashFunc = crypto.SHA384
	case asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_512,
		asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_512,
		asymkms.AsymmetricSignatureAlgorithm_RSA_4096_SIGN_PSS_SHA_512:
		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("public key is not RSA")
		}

		signatureKey.Verifier, err = signature.LoadRSAPSSVerifier(rsaPubKey, crypto.SHA512, nil)
		signatureKey.HashFunc = crypto.SHA512
	case asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P256_SHA_256:
		ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("public key is not ECDSA")
		}

		signatureKey.Verifier, err = signature.LoadECDSAVerifier(ecdsaPubKey, crypto.SHA256)
		signatureKey.HashFunc = crypto.SHA256
	case asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P384_SHA_384:
		ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("public key is not ECDSA")
		}

		signatureKey.Verifier, err = signature.LoadECDSAVerifier(ecdsaPubKey, crypto.SHA384)
		signatureKey.HashFunc = crypto.SHA384
	case asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P521_SHA_512:
		ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("public key is not ECDSA")
		}

		signatureKey.Verifier, err = signature.LoadECDSAVerifier(ecdsaPubKey, crypto.SHA512)
		signatureKey.HashFunc = crypto.SHA512
	case asymkms.AsymmetricSignatureAlgorithm_ASYMMETRIC_SIGNATURE_ALGORITHM_UNSPECIFIED,
		asymkms.AsymmetricSignatureAlgorithm_ECDSA_SECP256_K1_SHA_256:
		return nil, errors.New("unsupported algorithm specified by KMS")
	}

	if err != nil {
		return nil, fmt.Errorf("initializing internal verifier: %w", err)
	}

	return &signatureKey, nil
}

func (y *ycKmsClient) getHashFunc(ctx context.Context) (crypto.Hash, error) {
	signatureKey, err := y.getSK(ctx)
	if err != nil {
		return 0, err
	}

	return signatureKey.HashFunc, nil
}

func (y *ycKmsClient) getSK(ctx context.Context) (*ycSignatureKey, error) {
	var loaderErr error

	loader := ttlcache.LoaderFunc[string, ycSignatureKey](
		func(cache *ttlcache.Cache[string, ycSignatureKey], key string) *ttlcache.Item[string, ycSignatureKey] {
			signatureKey, err := y.getYcSignatureKey(ctx)
			if err != nil {
				loaderErr = err

				return nil
			}

			return cache.Set(key, *signatureKey, 5*time.Minute)
		},
	)

	item := y.skCache.Get(cacheKey, ttlcache.WithLoader[string, ycSignatureKey](loader))

	if loaderErr != nil {
		return nil, loaderErr
	}

	if item == nil {
		return nil, errors.New("signature key cache returned nil item")
	}

	signatureKey := item.Value()

	return &signatureKey, nil
}

func (y *ycKmsClient) createKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	if y.folderID == "" || y.keyName == "" {
		return nil, errors.New("generate yckms key specification should be in the format yckms://[ENDPOINT]/folder/FOLDER/keyname/KEYNAME")
	}

	signatureAlgorithm, ok := algorithmMap[algorithm]
	if !ok {
		return nil, errors.New("unknown algorithm requested")
	}

	createKeyRequest := &asymkms.CreateAsymmetricSignatureKeyRequest{
		SignatureAlgorithm: signatureAlgorithm,
		FolderId:           y.folderID,
		Name:               y.keyName,
		Description:        "Created by sigstore",
	}

	op, err := y.client.WrapOperation(y.client.KMSAsymmetricSignature().AsymmetricSignatureKey().Create(ctx, createKeyRequest))
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
		return nil, errors.New("failed to cast response to *asymkms.AsymmetricSignatureKey")
	}

	getPubKeyRequest := &asymkms.AsymmetricGetPublicKeyRequest{KeyId: key.Id}

	pubKey, err := y.client.KMSAsymmetricSignatureCrypto().AsymmetricSignatureCrypto().GetPublicKey(ctx, getPubKeyRequest)
	if err != nil {
		return nil, err
	}

	return cryptoutils.UnmarshalPEMToPublicKey([]byte(pubKey.GetPublicKey()))
}

func (y *ycKmsClient) verify(ctx context.Context, sig, message io.Reader, opts ...signature.VerifyOption) error {
	signatureKey, err := y.getSK(ctx)
	if err != nil {
		return err
	}

	return signatureKey.Verifier.VerifySignature(sig, message, opts...)
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

	return signResponse.Signature, nil
}

func (y *ycKmsClient) fetchPublicKey(ctx context.Context) (crypto.PublicKey, error) {
	getPubKeyRequest := &asymkms.AsymmetricGetPublicKeyRequest{KeyId: y.keyID}

	pubKey, err := y.client.KMSAsymmetricSignatureCrypto().AsymmetricSignatureCrypto().GetPublicKey(ctx, getPubKeyRequest)
	if err != nil {
		return nil, err
	}

	return cryptoutils.UnmarshalPEMToPublicKey([]byte(pubKey.GetPublicKey()))
}
