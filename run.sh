#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
export OMP_NUM_THREADS=2
export OPENBLAS_NUM_THREADS=1
export POLARS_MAX_THREADS=2
export MPLCONFIGDIR="$PWD/tools/matplotlib"
exec .venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port "${PORT:-8000}"
