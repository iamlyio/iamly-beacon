# Changelog

All notable changes to IAMly Beacon are documented here. The project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0-rc.6] - 2026-08-20

### Changed

- Beacon now uses the permanent `https://beacon.iamly.io` control-plane
  endpoint so installations keep the same address after the beta period.

## [2.2.0-rc.5] - 2026-08-20

### Added

- Cloudflare account-member collection through a dedicated API token with
  Account Settings Read, including invitation status, roles, and permission
  groups.
- Guided local-vault setup and least-privilege configuration documentation for
  Cloudflare.
- A `beacon upgrade` command that discovers or selects a release, verifies its
  checksum and embedded version, preserves the previous binary, and replaces
  the installed binary atomically on Linux and macOS.

## [2.2.0-rc.4] - 2026-08-19

### Changed

- The beta control plane is now the only supported enrollment and polling
  target; retired development routes are no longer accepted.
- Each collector has a ten-minute deadline, and evidence capture time is
  recorded after collection finishes.
- Collection results have a tested 32 MiB client-side upload boundary.

## [2.2.0-rc.3] - 2026-08-19

### Added

- npm organization member and role collection through a dedicated access token.
- Docker Hub organization member, invitation, role, and recent-activity
  collection through a personal or organization access token.
- Guided local-vault setup and installation documentation for both integrations.

## [2.2.0-rc.2] - 2026-08-19

### Added

- `--dev` selects the development control plane during installation and
  configuration.

### Changed

- Beacon now selects `https://beacon.iamly.io` by default instead of asking
  customers for a control-plane URL.
- The terminal interface now uses Bubble Tea v2 to prevent terminal capability
  replies from leaking into form fields over tmux and SSH.

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

[2.2.0-rc.5]: https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.5
[2.2.0-rc.4]: https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.4
[2.2.0-rc.3]: https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.3
[2.2.0-rc.2]: https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.2
[2.2.0-rc.1]: https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.1
[2.1.1]: https://github.com/iamlyio/iamly-beacon/blob/main/CHANGELOG.md#211---2026-08-18
[2.1.0]: https://github.com/iamlyio/iamly-beacon/blob/main/CHANGELOG.md#210---2026-08-18
[2.0.0]: https://github.com/iamlyio/iamly-beacon/blob/main/CHANGELOG.md#200---2026-08-18
[1.0.0]: https://github.com/iamlyio/iamly-beacon/blob/main/CHANGELOG.md#100---2026-08-17
