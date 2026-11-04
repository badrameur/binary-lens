from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parent
MAX_BYTES = 20 * 1024 * 1024
MAX_BODY = MAX_BYTES + 1024 * 1024
app = FastAPI(title="Binary Lens", version="1.0.0", docs_url=None, redoc_url=None)
slots = asyncio.Semaphore(1)


class BodyTooLarge(Exception):
    pass


class LimitsMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        length = headers.get(b"content-length", b"0")
        try:
            oversized = int(length) > MAX_BODY
        except ValueError:
            return await JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)(scope, receive, send)
        if oversized:
            return await JSONResponse({"detail": "Maximum file size is 20 MiB."}, status_code=413)(scope, receive, send)
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > MAX_BODY:
                    raise BodyTooLarge()
            return message

        async def secured_send(message):
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).extend([
                    (b"x-content-type-options", b"nosniff"),
                    (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"),
                    (b"cache-control", b"no-store"),
                ])
            await send(message)
        try:
            await self.app(scope, limited_receive, secured_send)
        except BodyTooLarge:
            await JSONResponse({"detail": "Maximum request size exceeded."}, status_code=413)(scope, receive, secured_send)


app.add_middleware(LimitsMiddleware)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/docs", include_in_schema=False)
def api_docs():
    return FileResponse(ROOT / "static" / "api.html")


@app.get("/api/status")
def status():
    metrics = ROOT / "reports" / "evaluation.json"
    return dict(name="Binary Lens", version="1.0.0", max_file_mib=20,
                models={fmt: (ROOT / "models" / f"EMBER2024_{fmt}.model").exists() for fmt in ["PE", "ELF"]},
                evaluation=json.loads(metrics.read_text()) if metrics.exists() else None)


@app.get("/api/demo")
def demo():
    sample = ROOT / "samples" / "system-true.elf"
    if not sample.exists():
        raise HTTPException(404, "Demo sample has not been built.")
    return FileResponse(sample, media_type="application/octet-stream", filename="system-true.elf")


@app.post("/api/analyze")
async def analyze_file(file: UploadFile = File(...), model_variant: str = Form("pretrained")):
    if model_variant not in {"pretrained", "student"}:
        raise HTTPException(400, "Unknown model choice.")
    data = bytearray()
    try:
        while chunk := await file.read(1024 * 1024):
            data.extend(chunk)
            if len(data) > MAX_BYTES:
                raise HTTPException(413, "Maximum file size is 20 MiB.")
    finally:
        await file.close()
    if not data:
        raise HTTPException(400, "The file is empty. Choose a PE or ELF file.")
    filename = (file.filename or "upload.bin").replace("\x00", "")[:240]
    async with slots:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, str(ROOT / "worker.py"), filename, model_variant,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, cwd=str(ROOT),
            env={**os.environ, "OMP_NUM_THREADS": "2", "OPENBLAS_NUM_THREADS": "1", "MPLCONFIGDIR": str(ROOT / "tools" / "matplotlib")},
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(bytes(data)), timeout=60)
        except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
            proc.kill()
            await proc.wait()
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise HTTPException(408, "Analysis exceeded 60 seconds. Try a smaller file.")
        try:
            result = json.loads(stdout)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise HTTPException(422, "The file could not be analyzed within the worker's resource limits.")
        if proc.returncode or "error" in result:
            raise HTTPException(422, result.get("error", "File analysis failed."))
        return result
