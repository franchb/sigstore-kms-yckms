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
	"fmt"
	"os"

	ycsdk "github.com/yandex-cloud/go-sdk"
	"github.com/yandex-cloud/go-sdk/iamkey"
)

func credentials(ctx context.Context) (ycsdk.Credentials, error) {
	if iamToken := os.Getenv(EnvYcIAMToken); iamToken != "" {
		return ycsdk.NewIAMTokenCredentials(iamToken), nil
	}

	if oauthToken := os.Getenv(EnvYcOAuthToken); oauthToken != "" {
		return ycsdk.OAuthToken(oauthToken), nil
	}

	if serviceAccountKeyFile := os.Getenv(EnvYcServiceAccountKeyFile); serviceAccountKeyFile != "" {
		key, err := iamkey.ReadFromJSONFile(serviceAccountKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read service account key file from %s: %w", EnvYcServiceAccountKeyFile, err)
		}

		return ycsdk.ServiceAccountKey(key)
	}

	creds := ycsdk.InstanceServiceAccount()
	if _, err := creds.IAMToken(ctx); err == nil {
		return creds, nil
	}

	return nil, fmt.Errorf("one of %s, %s, %s env variables must be set", EnvYcIAMToken, EnvYcOAuthToken, EnvYcServiceAccountKeyFile)
}
