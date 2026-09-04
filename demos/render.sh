#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -eq 0 ]]; then
  tapes=(quickstart post-solve-warning providers)
else
  tapes=("$@")
fi

for name in "${tapes[@]}"; do
  tape="demos/${name}.tape"
  if [[ ! -f "$tape" ]]; then
    echo "Unknown demo: ${name}" >&2
    exit 2
  fi
  vhs "$tape"
done
