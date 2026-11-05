#!/usr/bin/env bash
set -euo pipefail

version="${1:?Usage: bash scripts/package.sh VERSION OUTPUT_DIR}"
output="${2:?Usage: bash scripts/package.sh VERSION OUTPUT_DIR}"
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]]; then
  printf 'Invalid release version: %s\n' "$version" >&2
  exit 1
fi
mkdir -p "$output"
output="$(cd "$output" && pwd)"
staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os="${target%/*}"
  arch="${target#*/}"
  name="weft_${version}_${os}_${arch}"
  mkdir -p "$staging/$name"
  for command in weft weftd; do
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build \
      -trimpath -ldflags='-s -w' -o "$staging/$name/$command" "./cmd/$command"
  done
  cp README.md "$staging/$name/README.md"
  tar -czf "$output/$name.tar.gz" -C "$staging" "$name"
  printf 'Packaged %s\n' "$name"
done

# Hash only this version's archives, even when OUTPUT_DIR already has old files.
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$output" && sha256sum "weft_${version}_"*.tar.gz) > "$output/checksums.txt"
else
  (cd "$output" && shasum -a 256 "weft_${version}_"*.tar.gz) > "$output/checksums.txt"
fi
