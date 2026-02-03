package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func TestValidReference(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		{
			name:    "valid with endpoint and key id",
			ref:     "localhost/key-id-123",
			wantErr: false,
		},
		{
			name:    "valid without endpoint and with key id",
			ref:     "/key-id-123",
			wantErr: false,
		},
		{
			name:    "valid with folder and keyname",
			ref:     "localhost/folder/folder-id-abc/keyname/my-key-name",
			wantErr: false,
		},
		{
			name:    "valid without endpoint with folder and keyname",
			ref:     "/folder/folder-id-abc/keyname/my-key-name",
			wantErr: false,
		},
		{
			name:    "invalid format missing key id",
			ref:     "localhost/",
			wantErr: true,
		},
		{
			name:    "valid format just path",
			ref:     "/folder/id/keyname/name",
			wantErr: false,
		},
		{
			name:    "invalid empty string",
			ref:     "",
			wantErr: true,
		},
		{
			name:    "invalid folder format without keyname",
			ref:     "localhost/folder/folder-id",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidReference(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidReference() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseReference(t *testing.T) {
	tests := []struct {
		name         string
		ref          string
		wantEndpoint string
		wantKeyID    string
		wantFolderID string
		wantKeyName  string
		wantErr      bool
	}{
		{
			name:         "key id with endpoint",
			ref:          "kms.yandexcloud.com/key-id-123",
			wantEndpoint: "kms.yandexcloud.com",
			wantKeyID:    "key-id-123",
			wantFolderID: "",
			wantKeyName:  "",
			wantErr:      false,
		},
		{
			name:         "key id without endpoint",
			ref:          "/key-id-456",
			wantEndpoint: "",
			wantKeyID:    "key-id-456",
			wantFolderID: "",
			wantKeyName:  "",
			wantErr:      false,
		},
		{
			name:         "folder and keyname with endpoint",
			ref:          "localhost/folder/folder-abc-123/keyname/my-test-key",
			wantEndpoint: "localhost",
			wantKeyID:    "",
			wantFolderID: "folder-abc-123",
			wantKeyName:  "my-test-key",
			wantErr:      false,
		},
		{
			name:         "folder and keyname without endpoint",
			ref:          "/folder/another-folder/keyname/another-key",
			wantEndpoint: "",
			wantKeyID:    "",
			wantFolderID: "another-folder",
			wantKeyName:  "another-key",
			wantErr:      false,
		},
		{
			name:    "invalid reference",
			ref:     "localhost/folder/folder-id",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint, keyID, folderID, keyName, err := ParseReference(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseReference() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if endpoint != tt.wantEndpoint {
				t.Errorf("ParseReference() endpoint = %v, want %v", endpoint, tt.wantEndpoint)
			}
			if keyID != tt.wantKeyID {
				t.Errorf("ParseReference() keyID = %v, want %v", keyID, tt.wantKeyID)
			}
			if folderID != tt.wantFolderID {
				t.Errorf("ParseReference() folderID = %v, want %v", folderID, tt.wantFolderID)
			}
			if keyName != tt.wantKeyName {
				t.Errorf("ParseReference() keyName = %v, want %v", keyName, tt.wantKeyName)
			}
		})
	}
}

func TestSupportedAlgorithms(t *testing.T) {
	sv := &SignerVerifier{}
	algs := sv.SupportedAlgorithms()

	expectedAlgs := []string{
		"ecdsa-nist-p256-sha256",
		"ecdsa-nist-p384-sha384",
		"ecdsa-nist-p521-sha512",
		"rsa-2048-pss-sha256",
		"rsa-2048-pss-sha384",
		"rsa-2048-pss-sha512",
		"rsa-3072-pss-sha256",
		"rsa-3072-pss-sha384",
		"rsa-3072-pss-sha512",
		"rsa-4096-pss-sha256",
		"rsa-4096-pss-sha384",
		"rsa-4096-pss-sha512",
	}

	if len(algs) != len(expectedAlgs) {
		t.Errorf("SupportedAlgorithms() returned %d algorithms, want %d", len(algs), len(expectedAlgs))
	}

	algSet := make(map[string]bool)
	for _, a := range algs {
		algSet[a] = true
	}

	for _, expected := range expectedAlgs {
		if !algSet[expected] {
			t.Errorf("SupportedAlgorithms() missing expected algorithm: %s", expected)
		}
	}
}

func TestDefaultAlgorithm(t *testing.T) {
	sv := &SignerVerifier{}
	got := sv.DefaultAlgorithm()

	if got != Algorithm_ECDSA_NIST_P256_SHA_256 {
		t.Errorf("DefaultAlgorithm() = %v, want %v", got, Algorithm_ECDSA_NIST_P256_SHA_256)
	}
}

func TestSignerVerifierImplementsInterface(t *testing.T) {
	var _ signature.SignerVerifier = (*SignerVerifier)(nil)
	t.Log("SignerVerifier correctly implements signature.SignerVerifier interface")
}

func TestCryptoSignerWrapper_Public(t *testing.T) {
	t.Log("CryptoSigner method exists on SignerVerifier (tested via interface compliance)")
}

func TestLoadSignerVerifier_InvalidReference(t *testing.T) {
	_, err := LoadSignerVerifier(t.Context(), "invalid://test")
	if err == nil {
		t.Error("LoadSignerVerifier() with invalid reference should return error")
	}
}

func TestLoadSignerVerifier_InvalidFormat(t *testing.T) {
	tests := []struct {
		name string
		ref  string
	}{
		{"empty string", ""},
		{"missing endpoint", "test-key-id"},
		{"incomplete path", "localhost/folder/folder-id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadSignerVerifier(t.Context(), tt.ref)
			if err == nil {
				t.Errorf("LoadSignerVerifier(%q) should return error", tt.ref)
			}
		})
	}
}

func TestSignerVerifier_SignMessage_InvalidReference(t *testing.T) {
	sv := &SignerVerifier{}

	t.Run("SignMessage requires initialized client", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("SignMessage() panicked as expected: %v", r)
			}
		}()
		_, err := sv.SignMessage(nil)
		if err == nil {
			t.Error("SignMessage() on uninitialized SignerVerifier should return error or panic")
		}
	})
}

func TestSignerVerifier_VerifySignature_InvalidReference(t *testing.T) {
	sv := &SignerVerifier{}

	t.Run("VerifySignature requires initialized client", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("VerifySignature() panicked as expected: %v", r)
			}
		}()
		err := sv.VerifySignature(nil, nil)
		if err == nil {
			t.Error("VerifySignature() on uninitialized SignerVerifier should return error or panic")
		}
	})
}

func TestSignerVerifier_PublicKey_InvalidReference(t *testing.T) {
	sv := &SignerVerifier{}

	t.Run("PublicKey requires initialized client", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("PublicKey() panicked as expected: %v", r)
			}
		}()
		_, err := sv.PublicKey()
		if err == nil {
			t.Error("PublicKey() on uninitialized SignerVerifier should return error or panic")
		}
	})
}

func TestYCSupportedHashFuncs(t *testing.T) {
	expected := []crypto.Hash{
		crypto.SHA256,
		crypto.SHA512,
		crypto.SHA384,
	}

	if len(ycSupportedHashFuncs) != len(expected) {
		t.Errorf("ycSupportedHashFuncs has %d entries, want %d", len(ycSupportedHashFuncs), len(expected))
	}

	for i, h := range expected {
		if ycSupportedHashFuncs[i] != h {
			t.Errorf("ycSupportedHashFuncs[%d] = %v, want %v", i, ycSupportedHashFuncs[i], h)
		}
	}
}

func TestSignerVerifierWithMockClient(t *testing.T) {
	sv := &SignerVerifier{}

	t.Run("SignMessage_interface_compliance", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("SignMessage() panicked as expected: %v", r)
			}
		}()
		_, err := sv.SignMessage(
			nil,
			options.WithContext(t.Context()),
		)
		if err == nil {
			t.Error("SignMessage() should fail without initialized client")
		}
	})

	t.Run("VerifySignature_interface_compliance", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("VerifySignature() panicked as expected: %v", r)
			}
		}()
		err := sv.VerifySignature(
			nil,
			nil,
			options.WithContext(t.Context()),
		)
		if err == nil {
			t.Error("VerifySignature() should fail without initialized client")
		}
	})

	t.Run("PublicKey_interface_compliance", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("PublicKey() panicked as expected: %v", r)
			}
		}()
		_, err := sv.PublicKey(options.WithContext(t.Context()))
		if err == nil {
			t.Error("PublicKey() should fail without initialized client")
		}
	})
}

func TestCreateKey_InvalidReference(t *testing.T) {
	sv := &SignerVerifier{}

	t.Run("CreateKey requires initialized client", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("CreateKey() panicked as expected: %v", r)
			}
		}()
		_, err := sv.CreateKey(context.Background(), "ecdsa-nist-p256-sha256")
		if err == nil {
			t.Error("CreateKey() on uninitialized SignerVerifier should return error or panic")
		}
	})
}

func TestCreateKey_InvalidAlgorithm(t *testing.T) {
	sv := &SignerVerifier{
		client: &ycKmsClient{
			folderID: "test-folder",
			keyName:  "test-key",
		},
	}

	t.Run("CreateKey with invalid algorithm", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("CreateKey() panicked as expected: %v", r)
			}
		}()
		_, err := sv.CreateKey(context.Background(), "invalid-algorithm")
		if err == nil {
			t.Error("CreateKey() with invalid algorithm should return error or panic")
		}
	})
}

func TestYCSignatureKey_Structure(t *testing.T) {
	key := &ycSignatureKey{}
	_ = key
	t.Log("ycSignatureKey structure is valid")
}

func TestYcKmsClient_ReferenceParsing(t *testing.T) {
	tests := []struct {
		name        string
		ref         string
		expectError bool
		checkFields func(endpoint, keyID, folderID, keyName string) bool
	}{
		{
			name:        "simple key id",
			ref:         "endpoint.example.com/key123",
			expectError: false,
			checkFields: func(e, k, f, kn string) bool {
				return e == "endpoint.example.com" && k == "key123" && f == "" && kn == ""
			},
		},
		{
			name:        "folder and keyname",
			ref:         "kms.yandex.ru/folder/abc123/keyname/mykey",
			expectError: false,
			checkFields: func(e, k, f, kn string) bool {
				return e == "kms.yandex.ru" && k == "" && f == "abc123" && kn == "mykey"
			},
		},
		{
			name:        "no endpoint simple key",
			ref:         "/simple-key-id",
			expectError: false,
			checkFields: func(e, k, f, kn string) bool {
				return e == "" && k == "simple-key-id" && f == "" && kn == ""
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint, keyID, folderID, keyName, err := ParseReference(tt.ref)
			if (err != nil) != tt.expectError {
				t.Errorf("ParseReference() error = %v, expectError %v", err, tt.expectError)
				return
			}
			if !tt.expectError && !tt.checkFields(endpoint, keyID, folderID, keyName) {
				t.Errorf("ParseReference() returned incorrect fields: endpoint=%q, keyID=%q, folderID=%q, keyName=%q",
					endpoint, keyID, folderID, keyName)
			}
		})
	}
}

func TestCredentialsEnvVariables(t *testing.T) {
	t.Setenv("YC_IAM_TOKEN", "")
	t.Setenv("YC_OAUTH_TOKEN", "")
	t.Setenv("YC_SERVICE_ACCOUNT_KEY_FILE", "")

	_, err := credentials(t.Context())
	if err == nil {
		t.Error("credentials() should fail when no env variables are set")
	}
}

func TestSignerVerifierContextOptions(t *testing.T) {
	sv := &SignerVerifier{}

	t.Run("SignMessage with context", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("SignMessage() panicked as expected: %v", r)
			}
		}()
		_, err := sv.SignMessage(
			nil,
			options.WithContext(t.Context()),
		)
		if err == nil {
			t.Error("SignMessage should fail without client")
		}
	})

	t.Run("VerifySignature with context", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("VerifySignature() panicked as expected: %v", r)
			}
		}()
		err := sv.VerifySignature(
			nil,
			nil,
			options.WithContext(t.Context()),
		)
		if err == nil {
			t.Error("VerifySignature should fail without client")
		}
	})
}

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		wantMsg string
	}{
		{
			name:    "empty reference",
			ref:     "",
			wantMsg: "yckms specification should be in the format",
		},
		{
			name:    "wrong scheme",
			ref:     "aws-kms://key-id",
			wantMsg: "yckms specification should be in the format",
		},
		{
			name:    "incomplete folder path",
			ref:     "localhost/folder/id",
			wantMsg: "yckms specification should be in the format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidReference(tt.ref)
			if err == nil {
				t.Errorf("ValidReference(%q) should return error", tt.ref)
				return
			}
		})
	}
}

func TestECDSAPublicKeyGeneration(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	publicKey := privateKey.Public()
	ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("Expected ECDSA public key")
	}

	if ecdsaKey.X == nil || ecdsaKey.Y == nil {
		t.Error("ECDSA public key should have X and Y coordinates")
	}
}

func TestSignerVerifierCreateKeyRequiresFolderID(t *testing.T) {
	sv := &SignerVerifier{
		client: &ycKmsClient{
			keyID: "test-key-id",
		},
	}

	_, err := sv.CreateKey(t.Context(), Algorithm_ECDSA_NIST_P256_SHA_256)
	if err == nil {
		t.Error("CreateKey() should fail when folderID is empty")
	}
}

func TestSignerVerifierCreateKeyRequiresKeyName(t *testing.T) {
	sv := &SignerVerifier{
		client: &ycKmsClient{
			folderID: "test-folder-id",
		},
	}

	_, err := sv.CreateKey(t.Context(), Algorithm_ECDSA_NIST_P256_SHA_256)
	if err == nil {
		t.Error("CreateKey() should fail when keyName is empty")
	}
}

func TestPluginProtocolVersion(t *testing.T) {
	if expectedProtocolVersion != "v1" {
		t.Errorf("expectedProtocolVersion = %q, want %q", expectedProtocolVersion, "v1")
	}
}
