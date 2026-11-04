"""Download two public, pinned LightGBM text models; never downloads malware."""
import hashlib
import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REVISION = "e5b945dd90e1a1a1ec0cc07b3a17b52e9ba2d0c2"
EXPECTED_SHA256 = {
    "PE": "4252027863492ac138785c8c18576f43dad77d00faddc14e8c0072e8db419f99",
    "ELF": "8e4072938955ac6020f80bca6cff7c12e97865102d578b3099e2011048eb9c43",
}


def main():
    dest = ROOT / "models"
    dest.mkdir(exist_ok=True)
    manifest = {"repository": "joyce8/EMBER2024-benchmark-models", "revision": REVISION,
                "feature_source_commit": "0ef753e", "files": {}}
    for kind in ["PE", "ELF"]:
        name = f"EMBER2024_{kind}.model"
        path = dest / name
        url = f"https://huggingface.co/joyce8/EMBER2024-benchmark-models/resolve/{REVISION}/{name}"
        if not path.exists():
            print(f"Downloading {name}", flush=True)
            urllib.request.urlretrieve(url, path.with_suffix(".part"))
            path.with_suffix(".part").replace(path)
        if not path.read_bytes().startswith(b"tree\n"):
            raise ValueError(f"{name} is not a LightGBM text model")
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        if sha != EXPECTED_SHA256[kind]:
            raise ValueError(f"Checksum mismatch for pinned model {name}")
        manifest["files"][name] = {"sha256": sha, "bytes": path.stat().st_size, "source": url}
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Models ready. Provenance saved to models/manifest.json.")


if __name__ == "__main__":
    main()
