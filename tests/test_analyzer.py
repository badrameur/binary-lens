import io
import json
import math
import struct
import subprocess
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from analyzer import ROOT, analyze, entropy, inspect_structure
from app import app


def minimal_pe(bits=64, dll=False, native=False):
    """Non-running synthetic fixture: enough valid structure for PE parsers."""
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    opt_size = 240 if bits == 64 else 224
    characteristics = (0x22 if bits == 64 else 0x102) | (0x2000 if dll else 0)
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664 if bits == 64 else 0x14c, 1, 1700000000, 0, 0, opt_size, characteristics)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20b if bits == 64 else 0x10b)
    struct.pack_into("<I", data, opt + 4, 512)
    struct.pack_into("<I", data, opt + 16, 0x1000)
    struct.pack_into("<I", data, opt + 20, 0x1000)
    if bits == 64:
        struct.pack_into("<Q", data, opt + 24, 0x140000000)
        struct.pack_into("<I", data, opt + 108, 16)
    else:
        struct.pack_into("<I", data, opt + 28, 0x400000)
        struct.pack_into("<I", data, opt + 92, 16)
    struct.pack_into("<II", data, opt + 32, 0x1000, 512)
    struct.pack_into("<II", data, opt + 56, 0x2000, 512)
    struct.pack_into("<H", data, opt + 68, 1 if native else 3)
    section = opt + opt_size
    struct.pack_into("<8sIIIIIIHHI", data, section, b".text\0\0\0", 1, 0x1000, 512, 512, 0, 0, 0, 0, 0x60000020)
    data[512] = 0xc3
    return bytes(data)


def test_entropy_extremes():
    assert entropy(b"a" * 100) == 0
    assert entropy(bytes(range(256))) == pytest.approx(8)


@pytest.mark.parametrize("bits,dll,native,label", [(32,False,False,"executable"),(64,True,False,"library"),(64,False,True,"driver")])
def test_windows_categories_and_model_explanations(bits, dll, native, label):
    r = analyze(minimal_pe(bits, dll, native), "misleading.jpg")
    assert r["structure"]["format"] == "PE"
    assert label in r["structure"]["category"]
    p = r["prediction"]
    assert p["available"], p.get("error")
    assert p["model"] == "EMBER2024_PE.model"
    assert math.isfinite(p["score"]) and 0 <= p["score"] <= 1
    assert p["baseline"] + p["contribution_sum"] == pytest.approx(p["raw_score"], abs=1e-5)
    assert sum(x["contribution"] for x in p["groups"]) == pytest.approx(p["contribution_sum"])
    assert any("extension" in x for x in r["structure"]["warnings"])


def test_linux_pipeline_covers_final_byte_and_maps_real_regions():
    raw = (ROOT / "samples" / "system-true.elf").read_bytes()
    r = analyze(raw, "pretend.exe")
    assert r["structure"]["format"] == "ELF"
    assert r["prediction"]["available"], r["prediction"].get("error")
    assert r["prediction"]["model"] == "EMBER2024_ELF.model"
    assert sum(r["visuals"]["histogram"]) == len(raw)
    last = r["visuals"]["entropy_windows"][-1]
    assert last["offset"] + last["size"] == len(raw)
    assert r["structure"]["segments"]
    assert r["structure"]["sections"]


def test_linux_library_and_kernel_module_categories(tmp_path):
    lib = tmp_path / "sample.so"
    module = tmp_path / "sample.ko"
    source = tmp_path / "module.c"
    source.write_text('const char info[] __attribute__((section(".modinfo"))) = "license=GPL"; int sample(void){return 0;}')
    subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(lib), str(source)], check=True)
    subprocess.run(["gcc", "-c", "-o", str(module), str(source)], check=True)
    for file, category in [(lib, "shared library"), (module, "kernel module")]:
        r = analyze(file.read_bytes(), file.name)
        assert category in r["structure"]["category"]
        assert r["prediction"]["available"], r["prediction"].get("error")


def test_appended_content_is_observed_without_automatic_malware_claim():
    r = analyze(minimal_pe() + b"PK\x03\x04" + b"ordinary data" * 30, "example.exe")
    assert r["structure"]["trailing"]["size"] > 0
    assert any(x["title"] == "Appended bytes" for x in r["findings"])
    assert any(x["type"] == "ZIP" for x in r["embedded_signatures"])
    assert "not automatically" in next(x["detail"] for x in r["findings"] if x["title"] == "Appended bytes")


@pytest.mark.parametrize("data", [b"plain text file", b"MZbroken", b"\x7fELFbroken", b"\x89PNG\r\n\x1a\nanything"])
def test_unsupported_or_malformed_files_never_receive_a_malware_prediction(data):
    r = analyze(data, "file.exe")
    assert not r["prediction"]["available"]
    assert "score" not in r["prediction"]
    json.dumps(r, allow_nan=False)


def test_empty_file_rejected():
    with pytest.raises(ValueError, match="empty"):
        analyze(b"", "empty.exe")


def test_api_real_worker_upload_and_nonpersistent_result():
    client = TestClient(app)
    raw = (ROOT / "samples" / "system-true.elf").read_bytes()
    response = client.post("/api/analyze", files={"file": ("<script>alert(1)</script>.elf", raw)})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["prediction"]["available"], result["prediction"].get("error")
    assert result["sha256"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert "script-src 'self'" in response.headers["content-security-policy"]


def test_api_rejects_empty_and_oversize_requests():
    client = TestClient(app)
    assert client.post("/api/analyze", files={"file": ("empty", b"")}).status_code == 400
    response = client.post("/api/analyze", content=b"x", headers={"Content-Length": str(22 * 1024**2)})
    assert response.status_code == 413


def test_api_and_static_application_are_available():
    client = TestClient(app)
    assert client.get("/").status_code == 200
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/api/status").json()["models"] == {"PE": True, "ELF": True}
    assert client.get("/api/demo").content.startswith(b"\x7fELF")


def test_our_trained_model_can_be_used_on_real_elf_files():
    raw = (ROOT / "samples" / "system-true.elf").read_bytes()
    response = TestClient(app).post("/api/analyze", files={"file": ("demo.elf", raw)}, data={"model_variant": "student"})
    assert response.status_code == 200
    p = response.json()["prediction"]
    assert p["available"], p.get("error")
    assert p["model"] == "ELF_student.model"
    assert p["baseline"] + p["contribution_sum"] == pytest.approx(p["raw_score"], abs=1e-5)
    pe = analyze(minimal_pe(), "example.exe", "student")
    assert not pe["prediction"]["available"]
    assert "ELF files only" in pe["prediction"]["error"]


@pytest.mark.parametrize("bits", [32, 64])
def test_real_harmless_windows_launchers(bits):
    sample = ROOT / "samples" / f"python-launcher-win{bits}.exe"
    r = analyze(sample.read_bytes(), sample.name)
    assert r["structure"]["format"] == "PE"
    assert f"{bits}-bit" in r["structure"]["architecture"]
    assert r["structure"]["imports"]
    assert r["prediction"]["available"], r["prediction"].get("error")
