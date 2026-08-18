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

package main

import (
	"context"
	"errors"
	"fmt"
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
	if len(os.Args) < minPluginArgs {
		writeError(errMissingProtocolVersion)
	}

	if protocolVersion := os.Args[1]; protocolVersion != expectedProtocolVersion {
		writeError(fmt.Errorf("%w %s, got %s", errExpectedProtocolVersion, expectedProtocolVersion, protocolVersion))
	}

	pluginArgs, err := handler.GetPluginArgs(os.Args)
	if err != nil {
		writeError(err)
	}

	signerVerifier, err := yckms.LoadSignerVerifier(context.Background(), pluginArgs.InitOptions.KeyResourceID)
	if err != nil {
		writeError(err)
	}

	if _, err := handler.Dispatch(os.Stdout, os.Stdin, pluginArgs, signerVerifier); err != nil {
		os.Exit(1)
	}
}

// writeError reports err over the plugin protocol on stdout and exits non-zero.
// A failed write is unreportable — stdout is the only channel the protocol has.
func writeError(err error) {
	_ = handler.WriteErrorResponse(os.Stdout, err)

	os.Exit(1)
}
