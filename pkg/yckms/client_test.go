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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	asymkms "github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1/asymmetricsignature"
	ycsdk "github.com/yandex-cloud/go-sdk"
	"google.golang.org/grpc"
)

const testKeyResourceID = "/key-1"

var (
	errFakeBackendGetKey = errors.New("kms down")
	errFakeBackendPubKey = errors.New("public key unavailable")
	errFakeBackendCreate = errors.New("create failed")
	errFakeDial          = errors.New("dial blocked")
	errFakeVerifierPub   = errors.New("verifier public key")
)

type fakeBackend struct {
	priv      *ecdsa.PrivateKey
	pem       string
	keyID     string
	createID  string
	createPEM string
	getKeyErr error
	pubErr    error
	signErr   error
	createErr error
	alg       asymkms.AsymmetricSignatureAlgorithm
}

type stubVerifier struct {
	pub    crypto.PublicKey
	pubErr error
	sigErr error
}

func (s stubVerifier) PublicKey(...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return s.pub, s.pubErr
}

func (s stubVerifier) VerifySignature(io.Reader, io.Reader, ...signature.VerifyOption) error {
	return s.sigErr
}

func (f *fakeBackend) getKey(context.Context, string) (*asymkms.AsymmetricSignatureKey, error) {
	if f.getKeyErr != nil {
		return nil, f.getKeyErr
	}

	return &asymkms.AsymmetricSignatureKey{
		Id:                 f.keyID,
		FolderId:           "",
		CreatedAt:          nil,
		Name:               "",
		Description:        "",
		Labels:             nil,
		Status:             0,
		SignatureAlgorithm: f.alg,
		DeletionProtection: false,
	}, nil
}

func (f *fakeBackend) getPublicKeyPEM(context.Context, string) (string, error) {
	if f.pubErr != nil {
		return "", f.pubErr
	}

	return f.pem, nil
}

func (f *fakeBackend) signHash(_ context.Context, _ string, digest []byte) ([]byte, error) {
	if f.signErr != nil {
		return nil, f.signErr
	}

	signature, err := ecdsa.SignASN1(rand.Reader, f.priv, digest)
	if err != nil {
		return nil, fmt.Errorf("fake backend sign hash: %w", err)
	}

	return signature, nil
}

func (f *fakeBackend) createKey(
	context.Context,
	string,
	string,
	asymkms.AsymmetricSignatureAlgorithm,
) (string, string, error) {
	if f.createErr != nil {
		return "", "", f.createErr
	}

	return f.createID, f.createPEM, nil
}

func newTestClient(t *testing.T, backend kmsBackend, resourceID string) *ycKmsClient {
	t.Helper()

	if err := ValidReference(resourceID); err != nil {
		t.Fatal(err)
	}

	endpoint, keyID, folderID, keyName, err := ParseReference(resourceID)
	if err != nil {
		t.Fatal(err)
	}

	cache := ttlcache.New[string, ycSignatureKey](
		ttlcache.WithDisableTouchOnHit[string, ycSignatureKey](),
	)

	return &ycKmsClient{
		backend:   backend,
		skCache:   cache,
		endpoint:  endpoint,
		refString: resourceID,
		folderID:  folderID,
		keyID:     keyID,
		keyName:   keyName,
	}
}

func ecdsaFake(t *testing.T) *fakeBackend {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: der})

	return &fakeBackend{
		priv:      priv,
		pem:       string(pemBytes),
		keyID:     "key-1",
		createID:  "",
		createPEM: "",
		getKeyErr: nil,
		pubErr:    nil,
		signErr:   nil,
		createErr: nil,
		alg:       asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P256_SHA_256,
	}
}

func TestSignAndVerifyWithFakeBackend(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	client := newTestClient(t, fake, testKeyResourceID)
	sv := &SignerVerifier{client: client}

	message := []byte("hello-yckms")

	sig, err := sv.SignMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message)); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}

	pub, err := sv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	if _, err := cryptoutils.MarshalPublicKeyToPEM(pub); err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
}

func TestSignMessageUninitialized(t *testing.T) {
	t.Parallel()

	var sv *SignerVerifier

	_, err := sv.SignMessage(bytes.NewReader(nil))
	if !errors.Is(err, errUninitializedSignerVerifier) {
		t.Fatalf("error = %v", err)
	}

	if err := sv.VerifySignature(bytes.NewReader(nil), bytes.NewReader(nil)); !errors.Is(err, errUninitializedSignerVerifier) {
		t.Fatalf("error = %v", err)
	}

	if _, err := sv.PublicKey(); !errors.Is(err, errUninitializedSignerVerifier) {
		t.Fatalf("error = %v", err)
	}

	if _, err := sv.CreateKey(t.Context(), AlgorithmECDSANISTP256SHA256); !errors.Is(err, errUninitializedSignerVerifier) {
		t.Fatalf("error = %v", err)
	}

	if _, _, err := sv.CryptoSigner(t.Context(), nil); !errors.Is(err, errUninitializedSignerVerifier) {
		t.Fatalf("error = %v", err)
	}
}

func TestCreateKeyRequiresFolderAndName(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	sv := &SignerVerifier{client: newTestClient(t, fake, testKeyResourceID)}

	if _, err := sv.CreateKey(t.Context(), AlgorithmECDSANISTP256SHA256); !errors.Is(err, ErrCreateKeyReference) {
		t.Fatalf("error = %v, want ErrCreateKeyReference", err)
	}
}

func TestCreateKeyUnknownAlgorithm(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	sv := &SignerVerifier{client: newTestClient(t, fake, "host/folder/folder-1/keyname/k")}

	if _, err := sv.CreateKey(t.Context(), "not-an-alg"); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Fatalf("error = %v, want ErrUnknownAlgorithm", err)
	}
}

func TestCreateKeySuccess(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	fake.createID = "new-key"
	fake.createPEM = fake.pem
	sv := &SignerVerifier{client: newTestClient(t, fake, "host/folder/folder-1/keyname/k")}

	pub, err := sv.CreateKey(t.Context(), AlgorithmECDSANISTP256SHA256)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	if pub == nil {
		t.Fatal("nil public key")
	}
}

func TestGetSKBackendError(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	fake.getKeyErr = errFakeBackendGetKey
	sv := &SignerVerifier{client: newTestClient(t, fake, testKeyResourceID)}

	if _, err := sv.PublicKey(); err == nil {
		t.Fatal("expected error")
	}
}

func TestCryptoSignerSignsDigest(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	sv := &SignerVerifier{client: newTestClient(t, fake, testKeyResourceID)}

	cs, opts, err := sv.CryptoSigner(t.Context(), func(error) {})
	if err != nil {
		t.Fatalf("CryptoSigner: %v", err)
	}

	sum := sha256.Sum256([]byte("digest-me"))

	sig, err := cs.Sign(nil, sum[:], opts)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if len(sig) == 0 {
		t.Fatal("empty signature")
	}

	if cs.Public() == nil {
		t.Fatal("Public() nil")
	}
}

func TestAlgorithmMapCoversSupportedAlgorithms(t *testing.T) {
	t.Parallel()

	got := algorithmMap()
	for _, name := range (&SignerVerifier{}).SupportedAlgorithms() {
		if _, ok := got[name]; !ok {
			t.Fatalf("algorithmMap missing %s", name)
		}
	}
}

func TestVerifierForAlgorithmECDSAHashFuncs(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		alg  asymkms.AsymmetricSignatureAlgorithm
		hash crypto.Hash
	}{
		{asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P256_SHA_256, crypto.SHA256},
		{asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P384_SHA_384, crypto.SHA384},
		{asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P521_SHA_512, crypto.SHA512},
	}
	for _, tc := range cases {
		_, hashFunc, err := verifierForAlgorithm(tc.alg, priv.Public())
		if err != nil {
			t.Fatalf("alg %v: %v", tc.alg, err)
		}

		if hashFunc != tc.hash {
			t.Fatalf("hash = %v, want %v", hashFunc, tc.hash)
		}
	}
}

func TestVerifierForAlgorithmSecp256k1Unsupported(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = verifierForAlgorithm(
		asymkms.AsymmetricSignatureAlgorithm_ECDSA_SECP256_K1_SHA_256,
		priv.Public(),
	)
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("error = %v", err)
	}
}

func TestRSAHashVariants(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	_, hashFunc, err := verifierForAlgorithm(
		asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_512,
		rsaKey.Public(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if hashFunc != crypto.SHA512 {
		t.Fatalf("hash = %v, want SHA512", hashFunc)
	}
}

func TestPublicKeyBackendPublicKeyError(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	fake.pubErr = errFakeBackendPubKey
	sv := &SignerVerifier{client: newTestClient(t, fake, testKeyResourceID)}

	if _, err := sv.PublicKey(); err == nil {
		t.Fatal("expected error")
	}
}

func TestPublicKeyInvalidPEM(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	fake.pem = "not-a-pem"
	sv := &SignerVerifier{client: newTestClient(t, fake, testKeyResourceID)}

	if _, err := sv.PublicKey(); err == nil {
		t.Fatal("expected error")
	}
}

func TestPublicKeyUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	fake.alg = asymkms.AsymmetricSignatureAlgorithm_ECDSA_SECP256_K1_SHA_256
	sv := &SignerVerifier{client: newTestClient(t, fake, testKeyResourceID)}

	if _, err := sv.PublicKey(); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("error = %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestCreateKeyBackendError(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	fake.createErr = errFakeBackendCreate
	sv := &SignerVerifier{client: newTestClient(t, fake, "host/folder/folder-1/keyname/k")}

	if _, err := sv.CreateKey(t.Context(), AlgorithmECDSANISTP256SHA256); err == nil {
		t.Fatal("expected error")
	}
}

func TestCreateKeyInvalidPEM(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	fake.createID = "new-key"
	fake.createPEM = "not-a-pem"
	sv := &SignerVerifier{client: newTestClient(t, fake, "host/folder/folder-1/keyname/k")}

	if _, err := sv.CreateKey(t.Context(), AlgorithmECDSANISTP256SHA256); err == nil {
		t.Fatal("expected error")
	}
}

func TestVerifySignatureBackendError(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	fake.getKeyErr = errFakeBackendGetKey
	sv := &SignerVerifier{client: newTestClient(t, fake, testKeyResourceID)}

	err := sv.VerifySignature(bytes.NewReader(nil), bytes.NewReader(nil), options.WithContext(t.Context()))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestVerifySignatureRejectsBadMessage(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	sv := &SignerVerifier{client: newTestClient(t, fake, testKeyResourceID)}
	message := []byte("hello-yckms")

	sig, err := sv.SignMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader([]byte("other"))); err == nil {
		t.Fatal("expected verify error")
	}
}

func TestSignMessageBackendError(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	fake.getKeyErr = errFakeBackendGetKey
	sv := &SignerVerifier{client: newTestClient(t, fake, testKeyResourceID)}

	if _, err := sv.SignMessage(bytes.NewReader([]byte("hello-yckms"))); err == nil {
		t.Fatal("expected error")
	}
}

func TestSignMessageNilMessage(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	sv := &SignerVerifier{client: newTestClient(t, fake, testKeyResourceID)}

	if _, err := sv.SignMessage(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestCryptoSignerBackendError(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	fake.getKeyErr = errFakeBackendGetKey
	sv := &SignerVerifier{client: newTestClient(t, fake, testKeyResourceID)}

	if _, _, err := sv.CryptoSigner(t.Context(), nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestCryptoSignerPublicErrFunc(t *testing.T) {
	t.Parallel()

	var got error

	wrapper := cryptoSignerWrapper{
		ctx: t.Context(),
		sv:  &SignerVerifier{},
		errFunc: func(err error) {
			got = err
		},
		hashFunc: crypto.SHA256,
	}

	if pub := wrapper.Public(); pub != nil {
		t.Fatal("Public() = non-nil, want nil")
	}

	if got == nil {
		t.Fatal("errFunc was not called")
	}
}

func TestPublicKeyWrapsVerifierError(t *testing.T) {
	t.Parallel()

	fake := ecdsaFake(t)
	client := newTestClient(t, fake, testKeyResourceID)
	client.skCache.Set(cacheKey, ycSignatureKey{
		SignatureKey: &asymkms.AsymmetricSignatureKey{
			Id:                 fake.keyID,
			FolderId:           "",
			CreatedAt:          nil,
			Name:               "",
			Description:        "",
			Labels:             nil,
			Status:             0,
			SignatureAlgorithm: fake.alg,
			DeletionProtection: false,
		},
		Verifier: stubVerifier{
			pub:    nil,
			pubErr: errFakeVerifierPub,
			sigErr: nil,
		},
		HashFunc: crypto.SHA256,
	}, signatureKeyTTL)

	sv := &SignerVerifier{client: client}

	if _, err := sv.PublicKey(); !errors.Is(err, errFakeVerifierPub) {
		t.Fatalf("error = %v, want errFakeVerifierPub", err)
	}
}

func TestVerifierForAlgorithmUnknownValue(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	const unknownAlg asymkms.AsymmetricSignatureAlgorithm = 99

	_, _, err = verifierForAlgorithm(unknownAlg, priv.Public())
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("error = %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestSDKBackendWrapsTransportErrors(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	sdk, err := ycsdk.Build(ctx, ycsdk.Config{
		Credentials:        ycsdk.NewIAMTokenCredentials("test-token"),
		Endpoint:           "127.0.0.1:1",
		Plaintext:          true,
		DialContextTimeout: time.Millisecond,
		TLSConfig:          nil,
	}, grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return nil, errFakeDial
	}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	t.Cleanup(func() {
		_ = sdk.Shutdown(ctx)
	})

	backend := sdkBackend{sdk: sdk}

	if _, err := backend.getKey(ctx, "key-1"); err == nil {
		t.Fatal("getKey expected error")
	}

	if _, err := backend.getPublicKeyPEM(ctx, "key-1"); err == nil {
		t.Fatal("getPublicKeyPEM expected error")
	}

	if _, err := backend.signHash(ctx, "key-1", []byte("digest")); err == nil {
		t.Fatal("signHash expected error")
	}

	_, _, err = backend.createKey(
		ctx,
		"folder-1",
		"key-name",
		asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P256_SHA_256,
	)
	if err == nil {
		t.Fatal("createKey expected error")
	}
}
