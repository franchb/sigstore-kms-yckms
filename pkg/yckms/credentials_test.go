package yckms

import (
	"context"
	"testing"
	"time"
)

func TestCredentialsFailWhenNoSupportedSourceExists(t *testing.T) {
	t.Setenv(EnvYcIAMToken, "")
	t.Setenv(EnvYcOAuthToken, "")
	t.Setenv(EnvYcServiceAccountKeyFile, "")

	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()

	_, err := credentials(ctx)
	if err == nil {
		t.Fatal("credentials() succeeded without supported credential sources")
	}
}
