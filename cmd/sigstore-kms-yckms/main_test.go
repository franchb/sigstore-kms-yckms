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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"

	"github.com/franchb/sigstore-kms-yckms/pkg/yckms"
)

const pluginArgv0 = "sigstore-kms-yckms"

var errLoaderBoom = errors.New("loader boom")

func TestRunMissingProtocolVersion(t *testing.T) {
	t.Parallel()

	code, stdout := runPlugin(t, []string{pluginArgv0}, yckms.LoadSignerVerifier)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}

	if !strings.Contains(stdout, errMissingProtocolVersion.Error()) {
		t.Fatalf("stdout = %q, want %q", stdout, errMissingProtocolVersion)
	}
}

func TestRunWrongProtocolVersion(t *testing.T) {
	t.Parallel()

	code, stdout := runPlugin(t, []string{pluginArgv0, "v0"}, yckms.LoadSignerVerifier)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}

	if !strings.Contains(stdout, errExpectedProtocolVersion.Error()) {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestRunInvalidPluginJSON(t *testing.T) {
	t.Parallel()

	code, stdout := runPlugin(t, []string{pluginArgv0, expectedProtocolVersion, "{"}, yckms.LoadSignerVerifier)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}

	if stdout == "" {
		t.Fatal("expected plugin error JSON on stdout")
	}
}

func TestRunLoadSignerVerifierError(t *testing.T) {
	t.Parallel()

	args := []string{pluginArgv0, expectedProtocolVersion, defaultAlgorithmPluginJSON(t, "invalid")}

	code, stdout := runPlugin(t, args, yckms.LoadSignerVerifier)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}

	if !strings.Contains(stdout, yckms.ErrKMSReference.Error()) {
		t.Fatalf("stdout = %q, want ErrKMSReference", stdout)
	}
}

func TestRunDefaultAlgorithmWithoutKMS(t *testing.T) {
	t.Parallel()

	load := func(context.Context, string) (*yckms.SignerVerifier, error) {
		return &yckms.SignerVerifier{}, nil
	}

	args := []string{pluginArgv0, expectedProtocolVersion, defaultAlgorithmPluginJSON(t, "/key-id-123")}

	code, stdout := runPlugin(t, args, load)
	if code != 0 {
		t.Fatalf("run() = %d, stdout=%s", code, stdout)
	}

	if !strings.Contains(stdout, yckms.AlgorithmECDSANISTP256SHA256) {
		t.Fatalf("stdout = %q, want default algorithm", stdout)
	}
}

func TestExpectedProtocolVersion(t *testing.T) {
	t.Parallel()

	if expectedProtocolVersion != "v1" {
		t.Fatalf("expectedProtocolVersion = %q, want v1", expectedProtocolVersion)
	}
}

func TestRunLoaderError(t *testing.T) {
	t.Parallel()

	load := func(context.Context, string) (*yckms.SignerVerifier, error) {
		return nil, errLoaderBoom
	}

	args := []string{pluginArgv0, expectedProtocolVersion, defaultAlgorithmPluginJSON(t, "/key-id-123")}

	code, stdout := runPlugin(t, args, load)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}

	if !strings.Contains(stdout, errLoaderBoom.Error()) {
		t.Fatalf("stdout = %q", stdout)
	}
}

func runPlugin(
	t *testing.T,
	args []string,
	load func(context.Context, string) (*yckms.SignerVerifier, error),
) (int, string) {
	t.Helper()

	var stdout bytes.Buffer

	code := run(args, bytes.NewReader(nil), &stdout, load)

	return code, stdout.String()
}

func defaultAlgorithmPluginJSON(t *testing.T, keyResourceID string) string {
	t.Helper()

	payload, err := json.Marshal(common.PluginArgs{
		InitOptions: &common.InitOptions{
			CtxDeadline:     nil,
			ProtocolVersion: expectedProtocolVersion,
			KeyResourceID:   keyResourceID,
			HashFunc:        0,
			RPCOptions:      nil,
		},
		MethodArgs: &common.MethodArgs{
			MethodName:          common.DefaultAlgorithmMethodName,
			DefaultAlgorithm:    &common.DefaultAlgorithmArgs{},
			SupportedAlgorithms: nil,
			CreateKey:           nil,
			PublicKey:           nil,
			SignMessage:         nil,
			VerifySignature:     nil,
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return string(payload)
}
