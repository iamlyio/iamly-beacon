#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd)"
artifact_dir="${1:-$repo_root/dist}"
version="$(tr -d '[:space:]' < "$repo_root/VERSION")"

if [[ "$artifact_dir" != /* ]]; then
  artifact_dir="$repo_root/$artifact_dir"
fi
if [[ ! -f "$artifact_dir/SHA256SUMS" ]]; then
  echo "missing release checksums: $artifact_dir/SHA256SUMS" >&2
  exit 1
fi

expected=(
  iamly-beacon_linux_amd64.tar.gz
  iamly-beacon_linux_arm64.tar.gz
  iamly-beacon_darwin_amd64.tar.gz
  iamly-beacon_darwin_arm64.tar.gz
  iamly-beacon_windows_amd64.zip
  iamly-beacon_windows_arm64.zip
  iamly-beacon_sbom.cdx.json
)

for artifact in "${expected[@]}"; do
  if [[ ! -f "$artifact_dir/$artifact" ]]; then
    echo "missing release artifact: $artifact" >&2
    exit 1
  fi
done

(
  cd "$artifact_dir"
  sha256sum --check --strict SHA256SUMS
)

archive_listing="$(tar -tzf "$artifact_dir/iamly-beacon_linux_amd64.tar.gz" | LC_ALL=C sort)"
for member in LICENSE NOTICE README.md beacon; do
  if ! grep -Fxq "$member" <<< "$archive_listing"; then
    echo "Linux archive is missing $member" >&2
    exit 1
  fi
done

zip_listing="$(unzip -Z1 "$artifact_dir/iamly-beacon_windows_amd64.zip" | LC_ALL=C sort)"
for member in LICENSE NOTICE README.md beacon.exe; do
  if ! grep -Fxq "$member" <<< "$zip_listing"; then
    echo "Windows archive is missing $member" >&2
    exit 1
  fi
done

verification_dir="$(mktemp -d "${TMPDIR:-/tmp}/iamly-beacon-verify.XXXXXXXX")"
cleanup() {
  if [[ -d "$verification_dir" && "$(basename -- "$verification_dir")" == iamly-beacon-verify.* ]]; then
    rm -rf -- "$verification_dir"
  fi
}
trap cleanup EXIT
tar -xzf "$artifact_dir/iamly-beacon_linux_amd64.tar.gz" -C "$verification_dir" beacon
actual_version="$("$verification_dir/beacon" version)"
if [[ "$actual_version" != "Beacon v$version" ]]; then
  echo "unexpected binary version: $actual_version" >&2
  exit 1
fi

if ! grep -Fq '"bomFormat": "CycloneDX"' "$artifact_dir/iamly-beacon_sbom.cdx.json"; then
  echo "release SBOM is not CycloneDX JSON" >&2
  exit 1
fi

echo "release artifacts verified for Beacon v$version"
