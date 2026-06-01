package main

import "testing"

func TestExpectedProtocolVersion(t *testing.T) {
	t.Parallel()

	if expectedProtocolVersion != "v1" {
		t.Fatalf("expectedProtocolVersion = %q, want v1", expectedProtocolVersion)
	}
}
