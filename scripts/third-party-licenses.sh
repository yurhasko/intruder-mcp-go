#!/usr/bin/env bash
# Regenerates THIRD_PARTY_LICENSES.md from the modules linked into the binary.
# The release archives and the container image ship that file, because the
# binary is statically linked and the Apache, MIT and BSD terms it carries all
# require their notices to travel with it.
set -euo pipefail
cd "$(dirname "$0")/.."

out=THIRD_PARTY_LICENSES.md

{
  echo '# Third-party licenses'
  echo
  echo 'The `intruder-mcp` binary is statically linked and contains code from the'
  echo 'modules below. Their license texts are reproduced in full.'
  echo
  echo 'Regenerate with `bash scripts/third-party-licenses.sh`.'
} > "$out"

# Every module contributing a package to the binary, excluding this one and the
# standard library.
modules=$(go list -deps -f '{{with .Module}}{{.Path}}{{"\t"}}{{.Dir}}{{end}}' ./cmd/intruder-mcp |
  grep -v '^github.com/yurhasko/intruder-mcp-go' | sort -u)

missing=0
while IFS=$'\t' read -r path dir; do
  [[ -n $path && -n $dir ]] || continue

  license=$(find "$dir" -maxdepth 1 \( -iname 'LICENSE' -o -iname 'LICENSE.*' -o -iname 'COPYING' \) | sort | head -1)
  if [[ -z $license ]]; then
    echo "no license file found for $path in $dir" >&2
    missing=1
    continue
  fi

  {
    echo
    echo '---'
    echo
    echo "## $path"
    echo
    echo '```'
    cat "$license"
    echo '```'
  } >> "$out"
done <<< "$modules"

if [[ $missing -ne 0 ]]; then
  echo 'Refusing to write an incomplete notice file.' >&2
  exit 1
fi

echo "wrote $out"
