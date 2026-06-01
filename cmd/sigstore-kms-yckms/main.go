package main

import (
	"context"
	"fmt"
	"os"

	"github.com/fitzplsr/sigstore-kms-yckms/pkg/yckms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/handler"
)

const expectedProtocolVersion = "v1"

func main() {
	if len(os.Args) < 2 {
		handler.WriteErrorResponse(os.Stdout, fmt.Errorf("missing protocol version"))
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
