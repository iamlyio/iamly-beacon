# Changelog

All notable changes to IAMly Beacon are documented here. The project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Generic metadata-only Keys snapshots replace the deploy-key-only wire format.
  GitHub approved fine-grained PATs and active/disabled deploy keys retain independent
  coverage, bounded pagination, permission isolation, and explicit unknown
  creation/owner fields. GCP and AWS KMS encryption-key metadata share the same
  contract. Linear's public-API key inventory limitation is reported explicitly
  without fabricated records or collecting any secret values.

- Read-only Miro Enterprise organization-member collection, including deactivated
  users, guest and administrator roles, license names, and normalized activity.
  Guided `orgId`/token setup and a one-member connection probe require a Company
  Admin token with `organizations:read`; no boards or estimated spend are collected.

- An explicitly tagged `beacon-development` build can target a local Beacon API
  through `IAMLY_BEACON_CONTROL_PLANE_URL`. Release binaries continue to ignore
  that environment variable and enforce the canonical hosted control plane.

### Fixed

- Empty collection snapshots now upload an empty member array instead of JSON
  `null`, preserving the result contract when a connector returns no accounts.

- Key inventory sanitation now rejects whitespace-only identities and bounds
  coverage messages to the protocol's 500-character limit, preventing invalid
  metadata from rejecting otherwise usable collection results.
- Configuration now erases newly enrolled signing-key buffers on exit, and
  invalid vault payloads erase any partially decoded secrets before returning.
- Review orchestration uses the protocol-validated pending integration list
  directly, removing an unreachable fallback to already completed integrations.
- Synthetic UUID fixtures no longer trigger credential detection. Only their
  exact historical false-positive fingerprints are excluded from secret scans.

## [2.2.0-rc.11] - 2026-08-21

### Fixed

- Normalize BambooHR date-only hire dates to UTC timestamps before upload, and
  omit malformed hire dates so one invalid vendor value cannot reject a full
  employee snapshot.

## [2.2.0-rc.10] - 2026-08-20

### Added

- Best-effort current-month spend collection from OpenAI and Anthropic
  organization cost reports and Cloudflare account subscriptions. GitHub
  billing collection remains supported. Billing permission failures never
  discard a valid identity snapshot.

### Changed

- Cloudflare setup now requests the additional read-only `Billing Read`
  permission. Beacon normalizes recurring account subscription prices to a
  monthly amount and never estimates missing provider costs from public list
  prices.

## [2.2.0-rc.9] - 2026-08-20

### Changed

- Credential commands are now top-level: `beacon set`, `beacon test`,
  `beacon import`, and `beacon list`. The former `beacon secret ...` nesting
  has been removed.

## [2.2.0-rc.8] - 2026-08-20

### Changed

- Worker lifecycle, poll-failure, and heartbeat output now includes an RFC 3339
  UTC timestamp. Every successful control-plane poll emits an acknowledged,
  restored, or healthy heartbeat line for service debugging.

## [2.2.0-rc.7] - 2026-08-20

### Added

- Bounded, read-only connection probes for all supported integrations through
  `beacon secret test <integration>` and capability-gated tests requested from
  the IAMly control plane. Provider data and credentials remain local; only a
  sanitized outcome is returned.
- A success message after the first acknowledged control-plane heartbeat and
  after a connection recovers, without logging every successful poll.

### Changed

- Worker startup now reports that Beacon is starting instead of claiming a
  control-plane connection before the first acknowledged heartbeat.

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

[2.2.0-rc.11]: https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.11
[2.2.0-rc.10]: https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.10
[2.2.0-rc.9]: https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.9
[2.2.0-rc.8]: https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.8
[2.2.0-rc.7]: https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.7
[2.2.0-rc.6]: https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.6
[2.2.0-rc.5]: https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.5
[2.2.0-rc.4]: https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.4
[2.2.0-rc.3]: https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.3
[2.2.0-rc.2]: https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.2
[2.2.0-rc.1]: https://github.com/iamlyio/iamly-beacon/releases/tag/v2.2.0-rc.1
[2.1.1]: https://github.com/iamlyio/iamly-beacon/blob/main/CHANGELOG.md#211---2026-08-18
[2.1.0]: https://github.com/iamlyio/iamly-beacon/blob/main/CHANGELOG.md#210---2026-08-18
[2.0.0]: https://github.com/iamlyio/iamly-beacon/blob/main/CHANGELOG.md#200---2026-08-18
[1.0.0]: https://github.com/iamlyio/iamly-beacon/blob/main/CHANGELOG.md#100---2026-08-17
