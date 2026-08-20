#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/iamly-beacon-install-test.XXXXXXXX")
cleanup() {
  case "$test_root" in
    "${TMPDIR:-/tmp}"/iamly-beacon-install-test.*) rm -rf -- "$test_root" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

version="v$(tr -d '[:space:]' < "$repo_root/VERSION")"
case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "installer test requires Linux or macOS" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "installer test requires AMD64 or ARM64" >&2; exit 1 ;;
esac
archive="iamly-beacon_${os}_${arch}.tar.gz"

mkdir -p "$test_root/fixtures" "$test_root/mock-bin" "$test_root/package"
cat > "$test_root/package/beacon" <<EOF
#!/bin/sh
[ "\${1:-}" = version ] && { printf '%s\n' 'Beacon $version'; exit 0; }
exit 1
EOF
chmod 0755 "$test_root/package/beacon"
tar -czf "$test_root/fixtures/$archive" -C "$test_root/package" beacon
checksum=$(sha256sum "$test_root/fixtures/$archive" | awk '{ print $1 }')
printf '%s  %s\n' "$checksum" "$archive" > "$test_root/fixtures/SHA256SUMS"

cat > "$test_root/mock-bin/curl" <<'EOF'
#!/bin/sh
set -eu
destination=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) destination="$2"; shift 2 ;;
    --proto|--tlsv1.2) [ "$1" = --proto ] && shift 2 || shift ;;
    --fail|--silent|--show-error|--location) shift ;;
    *) url="$1"; shift ;;
  esac
done
[ -n "$destination" ] && [ -n "$url" ]
cp "$INSTALLER_FIXTURES/${url##*/}" "$destination"
EOF
chmod 0755 "$test_root/mock-bin/curl"

PATH="$test_root/mock-bin:$PATH" INSTALLER_FIXTURES="$test_root/fixtures" \
  IAMLY_BEACON_RELEASE_BASE=https://fixtures.invalid \
  "$repo_root/install.sh" --no-configure --install-dir "$test_root/bin"
[ -x "$test_root/bin/beacon" ]
[ "$("$test_root/bin/beacon" version)" = "Beacon $version" ]

if PATH="$test_root/mock-bin:$PATH" INSTALLER_FIXTURES="$test_root/fixtures" \
  IAMLY_BEACON_RELEASE_BASE=https://fixtures.invalid \
  "$repo_root/install.sh" --dev --install-dir "$test_root/dev-bin" \
  >"$test_root/dev.out" 2>"$test_root/dev.err"; then
  echo "installer accepted the retired --dev route" >&2
  exit 1
fi
grep -Fq 'unknown argument: --dev' "$test_root/dev.err"

printf 'corrupt' >> "$test_root/fixtures/$archive"
if PATH="$test_root/mock-bin:$PATH" INSTALLER_FIXTURES="$test_root/fixtures" \
  IAMLY_BEACON_RELEASE_BASE=https://fixtures.invalid \
  "$repo_root/install.sh" --no-configure --install-dir "$test_root/bad-bin" \
  >"$test_root/bad.out" 2>"$test_root/bad.err"; then
  echo "installer accepted an artifact with a bad checksum" >&2
  exit 1
fi
grep -Fq 'checksum verification failed' "$test_root/bad.err"

cat > "$test_root/package/beacon" <<'EOF'
#!/bin/sh
[ "${1:-}" = version ] && { echo 'Beacon v0.0.0'; exit 0; }
exit 1
EOF
chmod 0755 "$test_root/package/beacon"
tar -czf "$test_root/fixtures/$archive" -C "$test_root/package" beacon
checksum=$(sha256sum "$test_root/fixtures/$archive" | awk '{ print $1 }')
printf '%s  %s\n' "$checksum" "$archive" > "$test_root/fixtures/SHA256SUMS"
if PATH="$test_root/mock-bin:$PATH" INSTALLER_FIXTURES="$test_root/fixtures" \
  IAMLY_BEACON_RELEASE_BASE=https://fixtures.invalid \
  "$repo_root/install.sh" --no-configure --install-dir "$test_root/wrong-version-bin" \
  >"$test_root/version.out" 2>"$test_root/version.err"; then
  echo "installer accepted an artifact with the wrong embedded version" >&2
  exit 1
fi
grep -Fq 'release binary reported an unexpected version' "$test_root/version.err"

echo "installer tests passed"
