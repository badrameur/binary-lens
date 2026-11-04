#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo "This setup script targets Linux x86_64. See README.md for manual Python setup."
  exit 1
fi
mkdir -p tools models samples reports
uv_path="$PWD/tools/uv-x86_64-unknown-linux-gnu/uv"
if [[ ! -x "$uv_path" ]]; then
  curl --fail --location https://github.com/astral-sh/uv/releases/download/0.13.4/uv-x86_64-unknown-linux-gnu.tar.gz --output tools/uv.tar.gz
  tar -xzf tools/uv.tar.gz -C tools
fi
export UV_CACHE_DIR="$PWD/tools/cache"
export UV_PYTHON_INSTALL_DIR="$PWD/tools/python"
if [[ ! -x .venv/bin/python ]]; then
  "$uv_path" venv --python 3.12 .venv
fi
"$uv_path" pip install --python .venv/bin/python -r requirements.lock.txt
.venv/bin/python scripts/download_models.py
cp /usr/bin/true samples/system-true.elf
if command -v gcc >/dev/null 2>&1; then
  gcc -O2 -o samples/hello-linux.elf samples/hello.c
fi
echo "Setup complete. Start the application with: bash run.sh"
