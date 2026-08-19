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

## Verifying releases

Release archives carry a keyless [cosign](https://github.com/sigstore/cosign)
signature over the checksum file, plus SLSA build provenance.

Verify the checksums:

```sh
cosign verify-blob \
  --bundle sigstore-kms-yckms_<version>_checksums.txt.sigstore.json \
  --certificate-identity 'https://github.com/franchb/sigstore-kms-yckms/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  sigstore-kms-yckms_<version>_checksums.txt
```

Then verify an archive against those checksums, and its build provenance:

```sh
sha256sum --check --ignore-missing sigstore-kms-yckms_<version>_checksums.txt
gh attestation verify sigstore-kms-yckms_<version>_linux_amd64.tar.gz \
  --repo franchb/sigstore-kms-yckms \
  --signer-workflow franchb/sigstore-kms-yckms/.github/workflows/release.yml
```

Each archive also ships a [syft](https://github.com/anchore/syft) SBOM alongside it.

## Reproducing a release archive locally

Release binaries are built with `CGO_ENABLED=0` and `-trimpath` (see
`.goreleaser.yaml`). A snapshot of the same six platform archives, without
publishing or signing:

```sh
task snapshot
```

Artifacts land in `dist/`. Checksums in a snapshot are not release-signed;
use the Verifying releases commands on a published GitHub Release.

## Acknowledgements

This project is a fork of [`fitzplsr/sigstore-kms-yckms`](https://github.com/fitzplsr/sigstore-kms-yckms),
adopted and maintained under the `franchb` namespace. It follows the Sigstore CLI KMS plugin
pattern and is distributed under the Apache License 2.0; the copyright notices of The Sigstore
Authors and the upstream authors are retained in every source file.
