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
	"fmt"
	"regexp"
)

const (
	// ReferenceScheme is the URI scheme used by the sigstore KMS plugin registration.
	ReferenceScheme = "yckms://"
	// EnvYcIAMToken is the environment variable used for Yandex Cloud IAM token credentials.
	EnvYcIAMToken = "YC_IAM_TOKEN" //nolint:gosec // environment variable name, not a credential value
	// EnvYcOAuthToken is the environment variable used for Yandex Cloud OAuth token credentials.
	EnvYcOAuthToken = "YC_OAUTH_TOKEN" //nolint:gosec // environment variable name, not a credential value
	// EnvYcServiceAccountKeyFile is the environment variable used for service account key file credentials.
	EnvYcServiceAccountKeyFile = "YC_SERVICE_ACCOUNT_KEY_FILE"
)

var (
	createReferenceRE = regexp.MustCompile(`^([^/]*)/folder/([^/]+)/keyname/([^/]+)$`)
	keyIDReferenceRE  = regexp.MustCompile(`^([^/]*)/([^/]+)$`)
)

// ValidReference returns a non-nil error when ref is not a provider-stripped yckms resource ID.
func ValidReference(ref string) error {
	if createReferenceRE.MatchString(ref) || keyIDReferenceRE.MatchString(ref) {
		return nil
	}

	return ErrKMSReference
}

// ParseReference parses a provider-stripped yckms resource ID into endpoint and key creation fields.
func ParseReference(reference string) (string, string, string, string, error) {
	if matches := createReferenceRE.FindStringSubmatch(reference); matches != nil {
		return matches[1], "", matches[2], matches[3], nil
	}

	if matches := keyIDReferenceRE.FindStringSubmatch(reference); matches != nil {
		return matches[1], matches[2], "", "", nil
	}

	return "", "", "", "", fmt.Errorf("parse yckms reference %q: %w", reference, ErrKMSReference)
}
