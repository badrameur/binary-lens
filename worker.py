"""One bounded child process per uploaded file. Reads bytes from stdin only."""
import os
import sys
import json
import resource

os.environ["OMP_NUM_THREADS"] = "2"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["POLARS_MAX_THREADS"] = "2"
resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

if __name__ == "__main__":
    try:
        from analyzer import analyze, MAX_FILE_SIZE
        data = sys.stdin.buffer.read(MAX_FILE_SIZE + 1)
        result = analyze(data, sys.argv[1] if len(sys.argv) > 1 else "upload.bin", sys.argv[2] if len(sys.argv) > 2 else "pretrained")
        print(json.dumps(result, allow_nan=False))
    except Exception as exc:
        print(json.dumps({"error": f"{type(exc).__name__}: {str(exc)[:250]}"}))
        sys.exit(1)
