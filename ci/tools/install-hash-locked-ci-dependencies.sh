#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
  echo "install-hash-locked-ci-dependencies: no arguments are accepted" >&2
  exit 2
fi

script_path=${BASH_SOURCE[0]}
case "$script_path" in
  /*) ;;
  *) script_path="$PWD/$script_path" ;;
esac
script_dir=$(CDPATH='' cd -- "$(dirname -- "$script_path")" && pwd)
framework_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
cd "$framework_root"

python3 -m pip install --disable-pip-version-check --no-input --only-binary=:all: \
  --require-hashes -r requirements-ci.lock
python3 -m pip check
