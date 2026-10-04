#!/usr/bin/env bash
set -euo pipefail

release_version=${1:-dev}
if [[ ! $release_version =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo 'Version must contain only letters, digits, dots, underscores, or hyphens.' >&2
  exit 1
fi
cd "$(dirname "$0")/.."
if [[ ! -s go.sum ]]; then
  echo 'Run go mod tidy to resolve dependencies before building release archives.' >&2
  exit 1
fi
mkdir -p dist
release_stage=$(mktemp -d)
trap 'rm -rf -- "$release_stage"' EXIT

go mod verify
for release_os in darwin linux windows; do
  for release_arch in amd64 arm64; do
    release_name="intruder-mcp_${release_version}_${release_os}_${release_arch}"
    release_dir="$release_stage/$release_name"
    mkdir -p "$release_dir"
    release_binary=intruder-mcp
    if [[ $release_os == windows ]]; then release_binary+=.exe; fi
    CGO_ENABLED=0 GOOS="$release_os" GOARCH="$release_arch" \
      go build -mod=readonly -trimpath -buildvcs=false \
      -ldflags="-s -w -X main.version=$release_version" \
      -o "$release_dir/$release_binary" ./cmd/intruder-mcp
    cp LICENSE.md THIRD_PARTY_LICENSES.md README.md CONTRIBUTING.md "$release_dir/"
    if [[ $release_os == windows ]]; then
      (cd "$release_stage" && zip -qr - "$release_name") > "dist/$release_name.zip"
    else
      tar -czf "dist/$release_name.tar.gz" -C "$release_stage" "$release_name"
    fi
  done
done
(
  cd dist
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "intruder-mcp_${release_version}_"*.tar.gz "intruder-mcp_${release_version}_"*.zip
  else
    shasum -a 256 "intruder-mcp_${release_version}_"*.tar.gz "intruder-mcp_${release_version}_"*.zip
  fi
) > "dist/checksums_${release_version}.txt"
