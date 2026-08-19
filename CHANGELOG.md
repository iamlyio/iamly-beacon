# Changelog

All notable changes to iamly Beacon are documented here. The project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0-rc.1] - 2026-08-19

### Added

- Explicit `--local`, `--google-kms`, and `--aws-kms` vault-storage backends.
- Secure local wrapping keys and AWS KMS support through the default AWS
  credential chain.

### Changed

- Existing vaults now select their recorded provider automatically and can be
  re-wrapped with another provider through an explicit `configure` flag.

## [2.1.1] - 2026-08-18

### Added

- Public release documentation, contribution guidance, and security policy.
- Reproducible archives for Linux, macOS, and Windows on AMD64 and ARM64.
- SHA-256 checksums, a CycloneDX SBOM, and GitHub build provenance for release
  artifacts.
- Continuous integration, dependency updates, and an audited tag-driven release
  workflow.

### Changed

- Expanded installation and verification guidance for downloadable binaries.

## [2.1.0] - 2026-08-18

### Added

- Read-only collectors for GCP, Tailscale, Twingate, Notion, Figma, OpenAI,
  Anthropic, Linear, Vercel, Asana, and Canva.
- Shared normalization and bounded vendor-response handling across collectors.

## [2.0.0] - 2026-08-18

### Changed

- Hardened the local vault, control-plane protocol, service sandbox, and
  collector retry behavior for production use.

## [1.0.0] - 2026-08-17

### Added

- Initial Beacon collector, encrypted GCP KMS-backed vault, enrollment flow,
  signed control-plane protocol, and core SaaS collectors.

[2.2.0-rc.1]: https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.1
[2.1.1]: https://github.com/iamlyio/iamly-beacon/blob/main/CHANGELOG.md#211---2026-08-18
[2.1.0]: https://github.com/iamlyio/iamly-beacon/blob/main/CHANGELOG.md#210---2026-08-18
[2.0.0]: https://github.com/iamlyio/iamly-beacon/blob/main/CHANGELOG.md#200---2026-08-18
[1.0.0]: https://github.com/iamlyio/iamly-beacon/blob/main/CHANGELOG.md#100---2026-08-17
