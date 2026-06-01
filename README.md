# sigstore-kms-yckms

Yandex Cloud KMS provider for Sigstore.

The repository exposes two integration modes:

- `pkg/yckms` is an importable Go package implementing `kms.SignerVerifier`.
- `cmd/sigstore-kms-yckms` is a Sigstore CLI KMS plugin compatible with `yckms://...` key references.

The CLI plugin writes protocol responses to stdout and does not emit debug output to stderr by default.
