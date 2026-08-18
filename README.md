# sigstore-kms-yckms

Yandex Cloud KMS provider for Sigstore.

The repository exposes two integration modes:

- `pkg/yckms` is an importable Go package implementing `kms.SignerVerifier`.
- `cmd/sigstore-kms-yckms` is a Sigstore CLI KMS plugin compatible with `yckms://...` key references.

The CLI plugin writes protocol responses to stdout and does not emit debug output to stderr by default.

## Install

Install the CLI KMS plugin:

```sh
go install github.com/franchb/sigstore-kms-yckms/cmd/sigstore-kms-yckms@latest
```

Or use the signer as a library:

```go
import "github.com/franchb/sigstore-kms-yckms/pkg/yckms"
```

## Acknowledgements

This project is a fork of [`fitzplsr/sigstore-kms-yckms`](https://github.com/fitzplsr/sigstore-kms-yckms),
adopted and maintained under the `franchb` namespace. It follows the Sigstore CLI KMS plugin
pattern and is distributed under the Apache License 2.0; the copyright notices of The Sigstore
Authors and the upstream authors are retained in every source file.
