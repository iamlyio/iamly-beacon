#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd)"
output_dir="${DIST_DIR:-$repo_root/dist}"

if [[ "$output_dir" != /* ]]; then
  output_dir="$repo_root/$output_dir"
fi
if [[ -d "$output_dir" ]] && find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  echo "release output directory is not empty: $output_dir" >&2
  exit 1
fi

version="$(tr -d '[:space:]' < "$repo_root/VERSION")"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "VERSION is not valid Semantic Versioning: $version" >&2
  exit 1
fi
if [[ -n "${RELEASE_TAG:-}" && "$RELEASE_TAG" != "v$version" ]]; then
  echo "release tag $RELEASE_TAG does not match VERSION v$version" >&2
  exit 1
fi

source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$repo_root" log -1 --format=%ct)}"
if [[ ! "$source_date_epoch" =~ ^[0-9]+$ ]]; then
  echo "SOURCE_DATE_EPOCH must be a Unix timestamp" >&2
  exit 1
fi

mkdir -p "$output_dir"
staging_root="$(mktemp -d "${TMPDIR:-/tmp}/iamly-beacon-release.XXXXXXXX")"
cleanup() {
  if [[ -d "$staging_root" && "$(basename -- "$staging_root")" == iamly-beacon-release.* ]]; then
    rm -rf -- "$staging_root"
  fi
}
trap cleanup EXIT

platforms=(
  "linux amd64"
  "linux arm64"
  "darwin amd64"
  "darwin arm64"
  "windows amd64"
  "windows arm64"
)

for platform in "${platforms[@]}"; do
  read -r target_os target_arch <<< "$platform"
  package_dir="$staging_root/$target_os-$target_arch"
  binary_name="beacon"
  if [[ "$target_os" == windows ]]; then
    binary_name="beacon.exe"
  fi
  mkdir -p "$package_dir"

  (
    cd "$repo_root"
    CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
      go build -trimpath -buildvcs=true \
      -ldflags="-s -w -buildid= -X main.version=v$version" \
      -o "$package_dir/$binary_name" ./cmd/beacon
  )
  cp "$repo_root/LICENSE" "$repo_root/NOTICE" "$repo_root/README.md" "$package_dir/"
  touch -d "@$source_date_epoch" "$package_dir"/*

  archive_base="iamly-beacon_${target_os}_${target_arch}"
  if [[ "$target_os" == windows ]]; then
    (
      cd "$package_dir"
      zip -X -q "$output_dir/${archive_base}.zip" LICENSE NOTICE README.md "$binary_name"
    )
  else
    tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 \
      --numeric-owner -C "$package_dir" -cf - LICENSE NOTICE README.md "$binary_name" \
      | gzip -n > "$output_dir/${archive_base}.tar.gz"
  fi
done

(
  cd "$repo_root"
  go run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0 \
    app -licenses -json -noserial -notimestamp -output-version 1.6 \
    -output "$output_dir/iamly-beacon_sbom.cdx.json" -main cmd/beacon .
)

(
  cd "$output_dir"
  find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' \
    | LC_ALL=C sort \
    | xargs sha256sum > "$staging_root/SHA256SUMS"
  mv "$staging_root/SHA256SUMS" SHA256SUMS
)

echo "release artifacts written to $output_dir"
