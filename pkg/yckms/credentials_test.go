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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialsFailWhenNoSupportedSourceExists(t *testing.T) {
	t.Setenv(EnvYcIAMToken, "")
	t.Setenv(EnvYcOAuthToken, "")
	t.Setenv(EnvYcServiceAccountKeyFile, "")

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := credentials(ctx)
	if err == nil {
		t.Fatal("credentials() succeeded without supported credential sources")
	}
}

func TestCredentialsIAMToken(t *testing.T) {
	t.Setenv(EnvYcIAMToken, "iam-test-token")
	t.Setenv(EnvYcOAuthToken, "")
	t.Setenv(EnvYcServiceAccountKeyFile, "")

	creds, err := credentials(t.Context())
	if err != nil {
		t.Fatalf("credentials() error = %v", err)
	}

	if creds == nil {
		t.Fatal("credentials() returned nil")
	}
}

func TestCredentialsOAuthToken(t *testing.T) {
	t.Setenv(EnvYcIAMToken, "")
	t.Setenv(EnvYcOAuthToken, "oauth-test-token")
	t.Setenv(EnvYcServiceAccountKeyFile, "")

	creds, err := credentials(t.Context())
	if err != nil {
		t.Fatalf("credentials() error = %v", err)
	}

	if creds == nil {
		t.Fatal("credentials() returned nil")
	}
}

func TestCredentialsInvalidServiceAccountFile(t *testing.T) {
	t.Setenv(EnvYcIAMToken, "")
	t.Setenv(EnvYcOAuthToken, "")
	t.Setenv(EnvYcServiceAccountKeyFile, filepath.Join(t.TempDir(), "missing.json"))

	_, err := credentials(t.Context())
	if err == nil {
		t.Fatal("credentials() succeeded with missing service-account file")
	}
}

func TestCredentialsValidServiceAccountFile(t *testing.T) {
	path := writeSAFile(t)

	t.Setenv(EnvYcIAMToken, "")
	t.Setenv(EnvYcOAuthToken, "")
	t.Setenv(EnvYcServiceAccountKeyFile, path)

	creds, err := credentials(t.Context())
	if err != nil {
		t.Fatalf("credentials() error = %v", err)
	}

	if creds == nil {
		t.Fatal("credentials() returned nil")
	}
}

func writeSAFile(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: nil, Bytes: der})

	body, err := json.Marshal(map[string]string{
		"id":                 "key-id",
		"service_account_id": "sa-id",
		"private_key":        string(pemBytes),
	})
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "sa.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}
