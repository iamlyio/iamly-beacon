#!/bin/sh
set -eu

version="${IAMLY_BEACON_VERSION:-v2.2.0-rc.7}"
install_dir="${IAMLY_BEACON_INSTALL_DIR:-${HOME}/.local/bin}"
release_base="${IAMLY_BEACON_RELEASE_BASE:-https://github.com/iamlyio/iamly-beacon/releases/download}"
configure=true

usage() {
  cat <<'EOF'
Install iamly Beacon from a checksum-verified GitHub Release.

Usage: install.sh [--version TAG] [--install-dir DIRECTORY] [--no-configure]

Environment:
  IAMLY_BEACON_VERSION       Release tag to install
  IAMLY_BEACON_INSTALL_DIR   Installation directory
  IAMLY_BEACON_RELEASE_BASE  Release download base (primarily for testing)
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      [ "$#" -ge 2 ] || { echo "install.sh: --version requires a tag" >&2; exit 2; }
      version="$2"
      shift 2
      ;;
    --install-dir)
      [ "$#" -ge 2 ] || { echo "install.sh: --install-dir requires a directory" >&2; exit 2; }
      install_dir="$2"
      shift 2
      ;;
    --no-configure)
      configure=false
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "install.sh: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if ! printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
  echo "install.sh: invalid release tag: $version" >&2
  exit 2
fi
[ -n "$install_dir" ] || { echo "install.sh: installation directory is empty" >&2; exit 2; }

for command_name in curl tar awk grep mktemp install mkdir mv rm uname; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "install.sh: required command not found: $command_name" >&2
    exit 1
  }
done

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *)
    echo "install.sh: supported operating systems are Linux and macOS" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *)
    echo "install.sh: supported architectures are AMD64 and ARM64" >&2
    exit 1
    ;;
esac

archive="iamly-beacon_${os}_${arch}.tar.gz"
temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/iamly-beacon-install.XXXXXXXX")
temporary_binary=""
cleanup() {
  if [ -n "$temporary_binary" ]; then
    rm -f -- "$temporary_binary"
  fi
  case "$temporary_dir" in
    "${TMPDIR:-/tmp}"/iamly-beacon-install.*) rm -rf -- "$temporary_dir" ;;
  esac
}
trap cleanup EXIT HUP INT TERM
umask 077

download() {
  destination="$1"
  url="$2"
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    --output "$destination" "$url"
}

artifact_url="$release_base/$version/$archive"
checksums_url="$release_base/$version/SHA256SUMS"
download "$temporary_dir/$archive" "$artifact_url"
download "$temporary_dir/SHA256SUMS" "$checksums_url"

expected_checksum=$(awk -v artifact="$archive" '$2 == artifact { print $1 }' "$temporary_dir/SHA256SUMS")
if ! printf '%s\n' "$expected_checksum" | grep -Eq '^[0-9a-f]{64}$'; then
  echo "install.sh: release checksums do not contain exactly one valid entry for $archive" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  actual_checksum=$(sha256sum "$temporary_dir/$archive" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
  actual_checksum=$(shasum -a 256 "$temporary_dir/$archive" | awk '{ print $1 }')
else
  echo "install.sh: sha256sum or shasum is required" >&2
  exit 1
fi
if [ "$actual_checksum" != "$expected_checksum" ]; then
  echo "install.sh: checksum verification failed for $archive" >&2
  exit 1
fi

tar -xzf "$temporary_dir/$archive" -C "$temporary_dir" beacon
if [ ! -f "$temporary_dir/beacon" ] || [ -L "$temporary_dir/beacon" ]; then
  echo "install.sh: release archive does not contain a regular Beacon binary" >&2
  exit 1
fi
artifact_version=$("$temporary_dir/beacon" version)
if [ "$artifact_version" != "Beacon $version" ]; then
  echo "install.sh: release binary reported an unexpected version: $artifact_version" >&2
  exit 1
fi

if [ -e "$install_dir" ] && [ ! -d "$install_dir" ]; then
  echo "install.sh: installation path is not a directory: $install_dir" >&2
  exit 1
fi
if [ -L "$install_dir" ]; then
  echo "install.sh: refusing to install through a symbolic-link directory: $install_dir" >&2
  exit 1
fi
mkdir -p "$install_dir"
temporary_binary="$install_dir/.beacon.install.$$"
install -m 0755 "$temporary_dir/beacon" "$temporary_binary"
mv -f -- "$temporary_binary" "$install_dir/beacon"
temporary_binary=""

installed_version=$("$install_dir/beacon" version)
if [ "$installed_version" != "Beacon $version" ]; then
  echo "install.sh: installed binary reported an unexpected version: $installed_version" >&2
  exit 1
fi

printf 'Installed %s at %s\n' "$installed_version" "$install_dir/beacon"
case ":${PATH:-}:" in
  *":$install_dir:"*) ;;
  *) printf 'Add %s to PATH before invoking beacon directly.\n' "$install_dir" ;;
esac

if [ "$configure" = true ]; then
  if [ -t 1 ] && [ -r /dev/tty ] && [ -w /dev/tty ]; then
    printf '\nStarting guided setup against https://beacon.iamly.io.\n' >/dev/tty
    "$install_dir/beacon" configure --local </dev/tty >/dev/tty 2>/dev/tty
  else
    printf '\nInstallation complete. Run this from an interactive terminal:\n  beacon configure --local\n'
  fi
fi

printf '\n%s\n' "Next: configure a collector with 'beacon secret set <integration>', then run 'beacon run'."
