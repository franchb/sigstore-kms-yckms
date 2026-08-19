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
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/handler"

	"github.com/franchb/sigstore-kms-yckms/pkg/yckms"
)

const (
	expectedProtocolVersion = "v1"

	// minPluginArgs is the argv length required to carry a protocol version.
	minPluginArgs = 2
)

var (
	errMissingProtocolVersion  = errors.New("missing protocol version")
	errExpectedProtocolVersion = errors.New("expected protocol version")
)

func main() {
	os.Exit(run(os.Args, os.Stdin, os.Stdout, yckms.LoadSignerVerifier))
}

func run(
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	load func(context.Context, string) (*yckms.SignerVerifier, error),
) int {
	if len(args) < minPluginArgs {
		return writeError(stdout, errMissingProtocolVersion)
	}

	if protocolVersion := args[1]; protocolVersion != expectedProtocolVersion {
		return writeError(
			stdout,
			fmt.Errorf("%w %s, got %s", errExpectedProtocolVersion, expectedProtocolVersion, protocolVersion),
		)
	}

	pluginArgs, err := handler.GetPluginArgs(args)
	if err != nil {
		return writeError(stdout, err)
	}

	signerVerifier, err := load(context.Background(), pluginArgs.InitOptions.KeyResourceID)
	if err != nil {
		return writeError(stdout, err)
	}

	if _, err := handler.Dispatch(stdout, stdin, pluginArgs, signerVerifier); err != nil {
		return 1
	}

	return 0
}

func writeError(stdout io.Writer, err error) int {
	_ = handler.WriteErrorResponse(stdout, err)

	return 1
}
