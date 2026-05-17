#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
python tools/demo/run_showcase.py "$@"
