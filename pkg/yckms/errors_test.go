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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	asymkms "github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1/asymmetricsignature"
)

func TestVerifierForAlgorithmRejectsMismatchedKeyType(t *testing.T) {
	t.Parallel()

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}

	// An RSA algorithm with an ECDSA key must report ErrPublicKeyNotRSA.
	_, _, err = verifierForAlgorithm(
		asymkms.AsymmetricSignatureAlgorithm_RSA_2048_SIGN_PSS_SHA_256,
		ecdsaKey.Public(),
	)
	if !errors.Is(err, ErrPublicKeyNotRSA) {
		t.Fatalf("verifierForAlgorithm() error = %v, want ErrPublicKeyNotRSA", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	// An ECDSA algorithm with an RSA key must report ErrPublicKeyNotECDSA.
	_, _, err = verifierForAlgorithm(
		asymkms.AsymmetricSignatureAlgorithm_ECDSA_NIST_P256_SHA_256,
		rsaKey.Public(),
	)
	if !errors.Is(err, ErrPublicKeyNotECDSA) {
		t.Fatalf("verifierForAlgorithm() error = %v, want ErrPublicKeyNotECDSA", err)
	}
}

func TestVerifierForAlgorithmRejectsUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	_, _, err = verifierForAlgorithm(
		asymkms.AsymmetricSignatureAlgorithm_ASYMMETRIC_SIGNATURE_ALGORITHM_UNSPECIFIED,
		rsaKey.Public(),
	)
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("verifierForAlgorithm() error = %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestVerifierForAlgorithmReturnsExpectedHash(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	verifier, hashFunc, err := verifierForAlgorithm(
		asymkms.AsymmetricSignatureAlgorithm_RSA_3072_SIGN_PSS_SHA_384,
		rsaKey.Public(),
	)
	if err != nil {
		t.Fatalf("verifierForAlgorithm() unexpected error: %v", err)
	}

	if verifier == nil {
		t.Fatal("verifierForAlgorithm() returned a nil verifier")
	}

	if hashFunc != crypto.SHA384 {
		t.Fatalf("verifierForAlgorithm() hash = %v, want %v", hashFunc, crypto.SHA384)
	}
}
