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
