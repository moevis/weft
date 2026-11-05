#!/usr/bin/env bash
set -euo pipefail

repo="${1:-${WEFT_REPO:-}}"
version="${WEFT_VERSION:-latest}"
install_dir="${WEFT_INSTALL_DIR:-$HOME/.local/bin}"
if [[ ! "$repo" =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ ]]; then
  printf 'Usage: bash install.sh OWNER/REPO\n' >&2
  exit 1
fi
for tool in curl tar; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'Required command: %s\n' "$tool" >&2; exit 1; }
done
case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) printf 'Supported systems: Linux and macOS\n' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) printf 'Supported architectures: amd64 and arm64\n' >&2; exit 1 ;;
esac
if [[ "$version" == latest ]]; then
  url="$(curl --proto '=https' --proto-redir '=https' -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest")"
  version="${url##*/}"
fi
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]]; then
  printf 'Cannot resolve a release version: %s\n' "$version" >&2
  exit 1
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
name="weft_${version}_${os}_${arch}"
archive="$name.tar.gz"
base="https://github.com/$repo/releases/download/$version"
printf 'Downloading Weft %s (%s/%s)...\n' "$version" "$os" "$arch"
curl --proto '=https' --proto-redir '=https' -fsSL "$base/$archive" -o "$work/$archive"
curl --proto '=https' --proto-redir '=https' -fsSL "$base/checksums.txt" -o "$work/checksums.txt"
expected=""
while read -r digest file; do
  if [[ "$file" == "$archive" ]]; then
    if [[ -n "$expected" ]]; then printf 'Duplicate checksum entry\n' >&2; exit 1; fi
    expected="$digest"
  fi
done < "$work/checksums.txt"
if [[ ! "$expected" =~ ^[a-fA-F0-9]{64}$ ]]; then
  printf 'Missing or invalid checksum for %s\n' "$archive" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$work/$archive")"
else
  command -v shasum >/dev/null 2>&1 || { printf 'Required command: sha256sum or shasum\n' >&2; exit 1; }
  actual="$(shasum -a 256 "$work/$archive")"
fi
actual="${actual%% *}"
if [[ "$actual" != "$expected" ]]; then
  printf 'Checksum mismatch; nothing installed.\n' >&2
  exit 1
fi
# Extract only the expected executables, not arbitrary archive paths.
for binary in weft weftd; do
  tar -xOf "$work/$archive" "$name/$binary" > "$work/$binary"
  test -s "$work/$binary" || { printf 'Empty executable: %s\n' "$binary" >&2; exit 1; }
done
mkdir -p "$install_dir"
for binary in weft weftd; do
  staged="$(mktemp "$install_dir/.$binary.XXXXXX")"
  if ! { cp "$work/$binary" "$staged" && chmod 755 "$staged" && mv -f "$staged" "$install_dir/$binary"; }; then
    rm -f "$staged"
    exit 1
  fi
done
printf 'Installed weft and weftd to %s\n' "$install_dir"
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) printf 'Add this directory to PATH: %s\n' "$install_dir" ;;
esac
