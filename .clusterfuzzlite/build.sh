#!/bin/bash -eu
# compile_native_go_fuzzer generates a libFuzzer harness that imports
# github.com/AdamKorcz/go-118-fuzz-build/testing. Install it at compile time;
# do not add it to the module's go.mod (it is a CFL/OSS-Fuzz build dep).
# Pin matches OSS-Fuzz native Go builds (2025-05-20).
go install github.com/AdamKorcz/go-118-fuzz-build@v0.0.0-20250520111509-a70c2aa677fa
go get github.com/AdamKorcz/go-118-fuzz-build/testing@v0.0.0-20250520111509-a70c2aa677fa
compile_native_go_fuzzer github.com/franchb/sigstore-kms-yckms/pkg/yckms FuzzParseReference fuzz_parse_reference
