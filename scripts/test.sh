#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$root"
export PYTHONDONTWRITEBYTECODE=1
for script in install.sh audit.sh vpnctl.sh scripts/build.sh scripts/test.sh; do
  bash -n "$script"
done
./scripts/build.sh --check
exec python3 -m unittest discover -s tests -p 'test_*.py' -v
