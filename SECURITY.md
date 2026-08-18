# Security Policy

## Supported Versions

Only the latest released version of `sigstore-kms-yckms` receives security fixes.

## Reporting a Vulnerability

Report security vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/franchb/sigstore-kms-yckms/security/advisories/new).

Please do not open a public issue for a security report.

Include, where possible: the affected version, a description of the impact, and
steps to reproduce. You will receive an acknowledgement within seven days.

## Scope

This project is a Yandex Cloud KMS provider for Sigstore. Vulnerabilities in the
Yandex Cloud KMS service itself should be reported to Yandex Cloud; vulnerabilities
in Sigstore libraries should be reported to the [Sigstore project](https://github.com/sigstore/sigstore/security).

## Release Verification

Release artifacts are signed with [cosign](https://github.com/sigstore/cosign)
keyless signatures and carry SLSA build provenance. See the Verifying releases
section of `README.md`.
