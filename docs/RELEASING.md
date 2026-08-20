# Release process

Releases are built by GitHub Actions from signed, annotated Semantic Versioning
tags. The workflow cross-compiles Beacon, packages the license and README,
generates a CycloneDX SBOM and SHA-256 checksums, creates GitHub provenance
attestations, and publishes a GitHub Release.

## Prepare

1. Confirm the control-plane endpoints are reachable at
   `https://beacon.iamly.io`.
2. Update `VERSION` and `CHANGELOG.md`; they must describe the same version.
3. Run `make check`, `make release-snapshot`, and `make verify-release`.
4. Review the full diff and run a secret scan across Git history.
5. Merge the release commit to `main` and wait for CI to pass.

## Publish

Create and push a signed annotated tag. Do not move or reuse a published tag.

```sh
version="$(tr -d '[:space:]' < VERSION)"
git tag -s "v${version}" -m "iamly Beacon v${version}"
git push origin "v${version}"
```

The `Release` workflow validates the tag against `VERSION` before it publishes
anything. After it completes:

1. Download the release archives and `SHA256SUMS` from GitHub.
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
