# Public release checklist

Use this checklist for each public prerelease and stable release.

## Product and legal

- [x] Confirm Apache-2.0 is the intended license with the copyright owner.
- [x] Replace the public branch and tag history with the reviewed release tree
  in one root commit.
- [ ] Confirm the supported-version policy and community moderation channel.
- [ ] Confirm the target release matches `VERSION` and approve its changelog
  entry before tagging.

## Production readiness

- [x] Route `https://beacon.iamly.io/api/v1/beacon/*` to the IAMly control
  plane and verify TLS, proxy trust, rate limits, and request-size limits before
  publishing a beta release.
- [ ] Complete a new enrollment using the packaged binary and a single-use
  beta token.
- [ ] Run one end-to-end review with a least-privilege test integration.
- [ ] Confirm operational monitoring, audit logs, backup coverage, and a support
  owner for the public launch.

## Security and supply chain

- [ ] Scan all fetched Git refs and the complete uncommitted release tree with
  Gitleaks; require zero unallowlisted findings.
- [ ] Build every supported platform archive from the target tag, verify each
  checksum and embedded version, and recursively scan the archives and SBOM.
- [ ] Run formatting, module verification, tidy-diff, vet, race-enabled tests,
  and `govulncheck`; require zero reachable vulnerabilities.
- [ ] Repeat these checks from the final committed tag in GitHub Actions before
  publishing the release.

## GitHub repository settings

- [ ] Set the description, homepage, and topics (`iam`, `identity`, `security`,
  `access-review`, `go`).
- [x] Confirm the repository is public only after the production checks pass.
- [ ] Enable private vulnerability reporting, secret scanning, push protection,
  Dependabot security updates, and CodeQL default setup.
- [ ] Configure `main` rules to require a pull request, the `Verify` status
  check, conversation resolution, and protection from deletion and force push.
- [x] Configure `v*` tag rules to restrict creation and prevent updates or
  deletion.
- [x] Require an independent reviewer through the `release` Environment and
  limit it to `v*` tags.
- [x] Enable immutable releases and keep default workflow permissions read-only.
- [ ] Verify Issues are enabled and the issue forms render correctly.

## Publish

- [ ] Commit and push the release-preparation changes; wait for CI to pass.
- [ ] Create the signed annotated tag following [RELEASING.md](RELEASING.md).
- [ ] Confirm the release workflow publishes six archives, `SHA256SUMS`, and the
  CycloneDX SBOM.
- [ ] Verify GitHub provenance for at least one artifact on each operating
  system.
- [ ] Confirm the README's latest-release download links work without GitHub
  authentication.
- [ ] Announce the release only after a clean install and enrollment smoke test.
