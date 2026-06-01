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
