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

import "errors"

var (
	// ErrKMSReference is returned when a provider-stripped yckms resource ID is invalid.
	ErrKMSReference = errors.New("yckms specification should be in the format " +
		"yckms://[ENDPOINT]/KEY_ID or yckms://[ENDPOINT]/folder/FOLDER_ID/keyname/KEY_NAME; " +
		"pass resource IDs without yckms:// into pkg/yckms")

	// ErrCreateKeyReference is returned when key creation is requested without a folder and key name.
	ErrCreateKeyReference = errors.New("generate yckms key specification should be in the format " +
		"yckms://[ENDPOINT]/folder/FOLDER/keyname/KEYNAME")

	// ErrPublicKeyNotRSA is returned when the KMS reports an RSA algorithm but serves a non-RSA public key.
	ErrPublicKeyNotRSA = errors.New("public key is not RSA")

	// ErrPublicKeyNotECDSA is returned when the KMS reports an ECDSA algorithm but serves a non-ECDSA public key.
	ErrPublicKeyNotECDSA = errors.New("public key is not ECDSA")

	// ErrUnsupportedAlgorithm is returned when the KMS key uses an algorithm this package cannot verify.
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm specified by KMS")

	// ErrUnknownAlgorithm is returned when a requested algorithm name is not one of SupportedAlgorithms.
	ErrUnknownAlgorithm = errors.New("unknown algorithm requested")

	// ErrNoCredentials is returned when no Yandex Cloud credential source is configured.
	ErrNoCredentials = errors.New("no Yandex Cloud credentials configured")

	errUninitializedSignerVerifier = errors.New("yckms signer verifier is not initialized")
	errSignatureKeyCacheEmpty      = errors.New("signature key cache returned nil item")
	errUnexpectedCreateKeyResponse = errors.New("unexpected response type from yckms key create")
)
