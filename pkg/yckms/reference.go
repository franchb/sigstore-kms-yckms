package yckms

import (
	"errors"
	"fmt"
	"regexp"
)

const (
	ReferenceScheme            = "yckms://"
	EnvYcIAMToken              = "YC_IAM_TOKEN"   //nolint:gosec // environment variable name, not a credential value
	EnvYcOAuthToken            = "YC_OAUTH_TOKEN" //nolint:gosec // environment variable name, not a credential value
	EnvYcServiceAccountKeyFile = "YC_SERVICE_ACCOUNT_KEY_FILE"
)

var (
	ErrKMSReference = errors.New("yckms specification should be in the format yckms://[ENDPOINT]/KEY_ID or yckms://[ENDPOINT]/folder/FOLDER_ID/keyname/KEY_NAME; pass resource IDs without yckms:// into pkg/yckms")

	createReferenceRE = regexp.MustCompile(`^([^/]*)/folder/([^/]+)/keyname/([^/]+)$`)
	keyIDReferenceRE  = regexp.MustCompile(`^([^/]*)/([^/]+)$`)
)

func ValidReference(ref string) error {
	if createReferenceRE.MatchString(ref) || keyIDReferenceRE.MatchString(ref) {
		return nil
	}

	return ErrKMSReference
}

func ParseReference(reference string) (endpoint, keyID, folderID, keyName string, err error) {
	if matches := createReferenceRE.FindStringSubmatch(reference); matches != nil {
		return matches[1], "", matches[2], matches[3], nil
	}
	if matches := keyIDReferenceRE.FindStringSubmatch(reference); matches != nil {
		return matches[1], matches[2], "", "", nil
	}

	return "", "", "", "", fmt.Errorf("parse yckms reference %q: %w", reference, ErrKMSReference)
}
