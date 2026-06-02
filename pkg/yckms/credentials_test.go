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

//nolint:testpackage // credentials() is internal and needs direct coverage for fallback behavior.
package yckms

import (
	"context"
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
