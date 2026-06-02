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

	"github.com/fitzplsr/sigstore-kms-yckms/pkg/yckms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/handler"
)

const expectedProtocolVersion = "v1"

func main() {
	if len(os.Args) < 2 {
		handler.WriteErrorResponse(os.Stdout, errors.New("missing protocol version"))
		os.Exit(1)
	}

	if protocolVersion := os.Args[1]; protocolVersion != expectedProtocolVersion {
		handler.WriteErrorResponse(os.Stdout, fmt.Errorf("expected protocol version %s, got %s", expectedProtocolVersion, protocolVersion))
		os.Exit(1)
	}

	pluginArgs, err := handler.GetPluginArgs(os.Args)
	if err != nil {
		handler.WriteErrorResponse(os.Stdout, err)
		os.Exit(1)
	}

	signerVerifier, err := yckms.LoadSignerVerifier(context.Background(), pluginArgs.InitOptions.KeyResourceID)
	if err != nil {
		handler.WriteErrorResponse(os.Stdout, err)
		os.Exit(1)
	}

	if _, err := handler.Dispatch(os.Stdout, os.Stdin, pluginArgs, signerVerifier); err != nil {
		os.Exit(1)
	}
}
