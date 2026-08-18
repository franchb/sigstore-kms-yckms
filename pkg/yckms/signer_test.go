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
	"testing"

	"github.com/sigstore/sigstore/pkg/signature/kms"
)

func TestSignerVerifierImplementsKMSInterface(t *testing.T) {
	t.Parallel()

	var _ kms.SignerVerifier = (*SignerVerifier)(nil)
}

func TestLoadSignerVerifierRejectsInvalidReferenceBeforeCredentials(t *testing.T) {
	t.Parallel()

	_, err := LoadSignerVerifier(context.Background(), "invalid")
	if !errors.Is(err, ErrKMSReference) {
		t.Fatalf("LoadSignerVerifier() error = %v, want ErrKMSReference", err)
	}
}

func TestSupportedAlgorithmsIncludesECDSAAndRSAPSS(t *testing.T) {
	t.Parallel()

	got := (&SignerVerifier{}).SupportedAlgorithms()

	want := map[string]bool{
		AlgorithmECDSANISTP256SHA256:  false,
		AlgorithmRSA2048SignPSSSHA256: false,
	}
	for _, alg := range got {
		if _, ok := want[alg]; ok {
			want[alg] = true
		}
	}

	for alg, seen := range want {
		if !seen {
			t.Fatalf("SupportedAlgorithms() did not include %s; got %v", alg, got)
		}
	}
}

func TestDefaultAlgorithm(t *testing.T) {
	t.Parallel()

	if got := (&SignerVerifier{}).DefaultAlgorithm(); got != AlgorithmECDSANISTP256SHA256 {
		t.Fatalf("DefaultAlgorithm() = %q, want %q", got, AlgorithmECDSANISTP256SHA256)
	}
}

func TestSupportedHashFuncs(t *testing.T) {
	t.Parallel()

	want := []crypto.Hash{crypto.SHA256, crypto.SHA512, crypto.SHA384}
	if len(ycSupportedHashFuncs()) != len(want) {
		t.Fatalf("ycSupportedHashFuncs length = %d, want %d", len(ycSupportedHashFuncs()), len(want))
	}

	for index, hashFunc := range want {
		if got := ycSupportedHashFuncs()[index]; got != hashFunc {
			t.Fatalf("ycSupportedHashFuncs[%d] = %v, want %v", index, got, hashFunc)
		}
	}
}

func TestSignerVerifierRejectsUninitializedClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		check func(*testing.T, *SignerVerifier)
	}{
		{
			name: "SignMessage",
			check: func(t *testing.T, signerVerifier *SignerVerifier) {
				t.Helper()

				_, err := signerVerifier.SignMessage(nil)
				if !errors.Is(err, errUninitializedSignerVerifier) {
					t.Fatalf("SignMessage() error = %v, want errUninitializedSignerVerifier", err)
				}
			},
		},
		{
			name: "PublicKey",
			check: func(t *testing.T, signerVerifier *SignerVerifier) {
				t.Helper()

				_, err := signerVerifier.PublicKey()
				if !errors.Is(err, errUninitializedSignerVerifier) {
					t.Fatalf("PublicKey() error = %v, want errUninitializedSignerVerifier", err)
				}
			},
		},
		{
			name: "VerifySignature",
			check: func(t *testing.T, signerVerifier *SignerVerifier) {
				t.Helper()

				err := signerVerifier.VerifySignature(nil, nil)
				if !errors.Is(err, errUninitializedSignerVerifier) {
					t.Fatalf("VerifySignature() error = %v, want errUninitializedSignerVerifier", err)
				}
			},
		},
		{
			name: "CreateKey",
			check: func(t *testing.T, signerVerifier *SignerVerifier) {
				t.Helper()

				_, err := signerVerifier.CreateKey(context.Background(), AlgorithmECDSANISTP256SHA256)
				if !errors.Is(err, errUninitializedSignerVerifier) {
					t.Fatalf("CreateKey() error = %v, want errUninitializedSignerVerifier", err)
				}
			},
		},
		{
			name: "CryptoSigner",
			check: func(t *testing.T, signerVerifier *SignerVerifier) {
				t.Helper()

				_, _, err := signerVerifier.CryptoSigner(context.Background(), nil)
				if !errors.Is(err, errUninitializedSignerVerifier) {
					t.Fatalf("CryptoSigner() error = %v, want errUninitializedSignerVerifier", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_nil_receiver", func(t *testing.T) {
			t.Parallel()

			tt.check(t, nil)
		})

		t.Run(tt.name+"_nil_client", func(t *testing.T) {
			t.Parallel()

			tt.check(t, &SignerVerifier{})
		})
	}
}

func TestCreateKeyRejectsInvalidLocalStateBeforeCallingKMS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		client    *ycKmsClient
		algorithm string
	}{
		{
			client:    &ycKmsClient{keyID: "test-key-id"},
			algorithm: AlgorithmECDSANISTP256SHA256,
		},
		{
			client:    &ycKmsClient{folderID: "test-folder-id"},
			algorithm: AlgorithmECDSANISTP256SHA256,
		},
		{
			client:    &ycKmsClient{folderID: "test-folder-id", keyName: "test-key-name"},
			algorithm: "invalid-algorithm",
		},
	}

	for _, tt := range tests {
		signerVerifier := &SignerVerifier{client: tt.client}

		_, err := signerVerifier.CreateKey(context.Background(), tt.algorithm)
		if err == nil {
			t.Fatalf("CreateKey() succeeded with client %#v and algorithm %q", tt.client, tt.algorithm)
		}
	}
}
