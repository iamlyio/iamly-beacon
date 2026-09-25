# Release process

Releases are built by GitHub Actions from signed, annotated Semantic Versioning
tags. The workflow cross-compiles Beacon, packages the license and README,
generates a CycloneDX SBOM and SHA-256 checksums, creates GitHub provenance
attestations, and publishes a GitHub Release.

Automatic upgrades do not trust release-host checksums by themselves. Beacon
contains IAMly Ed25519 release public keys and verifies `SHA256SUMS.sig` before
it reads a checksum or executes an archive. GitHub attestations remain an
independent operator-facing provenance check.

## Protocol 2 coordinated release

Protocol 2 replaces GitHub-only deploy-key payloads with canonical metadata-only
`keys` and per-kind `keyCoverage`. There is no protocol 1 compatibility mode.
The HTTP `/api/v1/beacon/...` paths and Beacon signing identities stay unchanged.

Before publishing the API or app release, land the canonical
`protocol/v2/manifest.json` and `schema.json` in Beacon. Set
`protocol/BEACON_CONTRACT_REF` in both downstream repositories to that exact
published Beacon commit, and verify their mirrors match it byte-for-byte.
Do not reuse the old protocol 1 pin or point the pin at a moving branch.

Drain active reviews and pause new scheduling for the cutover. Apply the app's
forward Keys/AWS migrations and runtime grants first, then deploy compatible
app/worker and Beacon API images together and upgrade customer Beacons to the
protocol 2 signed release before resuming reviews. A mixed-version deployment
rejects polling/results as `unsupported_protocol`; do not treat that rejection
as an empty key inventory. Verify empty, complete, partial, and unavailable
coverage using local fixture collectors before release, without production
credentials. Preserve historical certified raw snapshots and signing keys.

Rollback must coordinate Beacon, API, and app/worker versions. An API-only
rollback to protocol 1 cannot receive protocol 2 results; keep scheduling paused
until the compatible set is restored. Forward migrations are not reversed by
an image rollback.

## Prepare

1. Confirm the control-plane endpoints are reachable at
   `https://beacon.iamly.io`.
2. Update `VERSION` and `CHANGELOG.md`; they must describe the same version.
3. Run `make check`, `make release-snapshot`, and `make verify-release`.
4. Review the full diff and run a secret scan across Git history.
5. Merge the release commit to `main` and wait for CI to pass.
6. Confirm the `BEACON_RELEASE_SIGNING_KEYS` Actions secret contains a JSON
   object that maps each active key ID to its base64 PKCS#8 Ed25519
   private key. Private keys must never enter the repository or release assets.

The active root key ID is `f882bde0611a0c11`. On the protected release host,
set the repository secret without printing or placing the private key on a
command line:

```sh
key_file=/secure/path/to/beacon-release-root-2026.pk8
{ printf '{"f882bde0611a0c11":"'; base64 -w0 "$key_file"; printf '"}\n'; } |
  gh secret set BEACON_RELEASE_SIGNING_KEYS --repo iamlyio/iamly-beacon
```

## Publish

Create and push a signed annotated tag. Do not move or reuse a published tag.

```sh
version="$(tr -d '[:space:]' < VERSION)"
git tag -s "v${version}" -m "iamly Beacon v${version}"
git push origin "v${version}"
```

The `Release` workflow validates the tag against `VERSION` before it publishes
anything. After it completes:

1. Download the release archives, `SHA256SUMS`, and `SHA256SUMS.sig` from GitHub.
2. Verify checksums and the GitHub attestation:

   ```sh
   sha256sum --check SHA256SUMS
   gh attestation verify iamly-beacon_linux_amd64.tar.gz \
     --repo iamlyio/iamly-beacon
   ```

3. Run `beacon version` from at least one Linux, macOS, and Windows artifact.
4. Complete a fresh enrollment against the IAMly control plane.
5. Confirm the release is marked latest and the installation links in the
   README resolve.

## Roll back

GitHub releases and tags are immutable provenance anchors. If a release is
faulty, mark it as not latest, document the issue, and publish a new patch
version. Do not replace artifacts or force-move the tag.

## Rotate the release signing key

1. Generate a new Ed25519 key outside the repository and protect its private
   key in the release secret store.
2. Add its public key and key ID to `trustedReleaseKeys` while the old key is
   still trusted.
3. Publish one transition release signed by both old and new keys.
4. Wait until the transition release is broadly installed before publishing
   releases signed only by the new key.
5. Remove the old public key in a later release. Keep the retired private key
   offline for the rollback and incident-response retention period.

The signed message includes the release version and exact checksum file. A
signature cannot be replayed under another tag. The updater also rejects any
target that is not newer than the running version.
