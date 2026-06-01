package yckms

import "testing"

func TestParseReferenceAcceptsPluginResourceID(t *testing.T) {
	t.Parallel()

	endpoint, keyID, folderID, keyName, err := ParseReference("/key-id-123")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}
	if endpoint != "" || keyID != "key-id-123" || folderID != "" || keyName != "" {
		t.Fatalf("ParseReference() = endpoint %q keyID %q folderID %q keyName %q", endpoint, keyID, folderID, keyName)
	}
}

func TestParseReferenceAcceptsProviderResourceID(t *testing.T) {
	t.Parallel()

	endpoint, keyID, folderID, keyName, err := ParseReference("kms.yandexcloud.net/folder/folder-1/keyname/releases")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}
	if endpoint != "kms.yandexcloud.net" || keyID != "" || folderID != "folder-1" || keyName != "releases" {
		t.Fatalf("ParseReference() = endpoint %q keyID %q folderID %q keyName %q", endpoint, keyID, folderID, keyName)
	}
}

func TestValidReferenceRejectsFullScheme(t *testing.T) {
	t.Parallel()

	if err := ValidReference("yckms:///key-id-123"); err == nil {
		t.Fatal("ValidReference() accepted full yckms scheme; provider registration must strip it first")
	}
}
