package yckms

import (
	"context"
	"crypto"
	"errors"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature/kms"
)

func TestSignerVerifierImplementsKMSInterface(t *testing.T) {
	t.Parallel()

	var _ kms.SignerVerifier = (*SignerVerifier)(nil)
}

func TestLoadSignerVerifierRejectsInvalidReferenceBeforeCredentials(t *testing.T) {
	t.Parallel()

	_, err := LoadSignerVerifier(context.Background(), "invalid")
	if !errors.Is(err, ErrKMSReference) {
		t.Fatalf("LoadSignerVerifier() error = %v, want ErrKMSReference", err)
	}
}

func TestSupportedAlgorithmsIncludesECDSAAndRSAPSS(t *testing.T) {
	t.Parallel()

	got := (&SignerVerifier{}).SupportedAlgorithms()
	want := map[string]bool{
		AlgorithmECDSANISTP256SHA256:  false,
		AlgorithmRSA2048SignPSSSHA256: false,
	}
	for _, alg := range got {
		if _, ok := want[alg]; ok {
			want[alg] = true
		}
	}
	for alg, seen := range want {
		if !seen {
			t.Fatalf("SupportedAlgorithms() did not include %s; got %v", alg, got)
		}
	}
}

func TestDefaultAlgorithm(t *testing.T) {
	t.Parallel()

	if got := (&SignerVerifier{}).DefaultAlgorithm(); got != AlgorithmECDSANISTP256SHA256 {
		t.Fatalf("DefaultAlgorithm() = %q, want %q", got, AlgorithmECDSANISTP256SHA256)
	}
}

func TestDefaultHashFunc(t *testing.T) {
	t.Parallel()

	if got := defaultHashFunc(); got != crypto.SHA256 {
		t.Fatalf("defaultHashFunc() = %v, want %v", got, crypto.SHA256)
	}
}
