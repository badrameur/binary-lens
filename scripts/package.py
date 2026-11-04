"""Package the school project without caches, interpreters or training archives."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT.parent / "binary-lens-school-project.zip"
EXCLUDED = {".venv", "tools", "data", "__pycache__", ".pytest_cache", ".git", "build", "dist"}


def main():
    count = 0
    with ZipFile(DEST, "w", ZIP_DEFLATED) as archive:
        for file in sorted(ROOT.rglob("*")):
            relative = file.relative_to(ROOT)
            if not file.is_file() or any(part in EXCLUDED or part.endswith(".egg-info") for part in relative.parts):
                continue
            if relative.as_posix() == "samples/system-true.elf":
                continue  # Setup prepares this GNU system binary locally.
            if file.suffix in {".pyc", ".log"}:
                continue
            archive.write(file, Path("binary-lens") / relative)
            count += 1
    with ZipFile(DEST) as archive:
        assert archive.testzip() is None
    print(f"Packaged {count} files: {DEST} ({DEST.stat().st_size / 1024**2:.2f} MiB)")


if __name__ == "__main__":
    main()
