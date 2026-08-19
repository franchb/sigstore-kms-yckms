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

## Security review (2026-08)

Reviewed 2026-08 as part of OpenSSF Best Practices gold work.

Trust boundary: this repository's plugin and `pkg/yckms` handling of
`yckms://` resource IDs and Yandex Cloud credentials (`YC_IAM_TOKEN`,
`YC_OAUTH_TOKEN`, `YC_SERVICE_ACCOUNT_KEY_FILE`). The plugin is a local
CLI helper; it is not a network server.

Out of scope for this review (report upstream): Yandex Cloud KMS itself,
and Sigstore libraries (`github.com/sigstore/sigstore`). See Scope above.

## Release Verification

Release artifacts are signed with [cosign](https://github.com/sigstore/cosign)
keyless signatures and carry SLSA build provenance. See the Verifying releases
section of `README.md`.
