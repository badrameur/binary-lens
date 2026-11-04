"""Static PE/ELF inspection and explanations from the actual EMBER2024 models.

No uploaded code is executed. Structural findings are deliberately independent
of model attributions. Feature extraction is the pinned upstream implementation.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import math
import re
import time
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pefile
from elftools.elf.elffile import ELFFile
from thrember.features import PEFeatureExtractor

ROOT = Path(__file__).resolve().parent
MAX_FILE_SIZE = 20 * 1024 * 1024
GROUP_LABELS = {
    "general": "File size, entropy & identity",
    "histogram": "Byte distribution",
    "byteentropy": "Local byte / entropy patterns",
    "strings": "Strings & text patterns",
    "header": "PE headers",
    "section": "PE sections & appended data",
    "imports": "Imported libraries & functions",
    "exports": "Exported functions",
    "datadirectories": "PE data directories",
    "richheader": "Compiler metadata",
    "authenticode": "Signature metadata",
    "pefilewarnings": "PE parsing warnings",
}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(data)
    return float(-np.sum(p * np.log2(p)))


def region(data, name, offset, size, permissions="", kind="section", address=0):
    offset, size = int(offset), int(size)
    actual = data[max(offset, 0):max(offset, 0) + max(size, 0)]
    return dict(name=str(name)[:160], offset=offset, size=size,
                available_size=len(actual), entropy=entropy(actual),
                permissions=permissions, kind=kind, address=int(address),
                out_of_bounds=offset < 0 or offset + size > len(data))


def inspect_structure(data: bytes, filename: str) -> dict:
    result = dict(format="Unknown", category="Unsupported file", architecture="Unknown",
                  entry_point=None, sections=[], segments=[], imports=[], exports=[],
                  resources=[], warnings=[], trailing=None, supported=False)
    if data.startswith(b"MZ"):
        try:
            pe = pefile.PE(data=data, fast_load=False)
            if len(pe.sections) > 4096:
                raise ValueError("Too many sections to inspect")
            bits = 64 if pe.OPTIONAL_HEADER.Magic == 0x20B else 32
            is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
            native = pe.OPTIONAL_HEADER.Subsystem == 1
            result.update(format="PE", architecture=f"{pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, 'unknown')} / {bits}-bit",
                          category="Windows driver (native subsystem)" if native else "Windows library (.dll)" if is_dll else "Windows executable (.exe)",
                          entry_point=hex(pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint), supported=True)
            for s in pe.sections:
                flags = s.Characteristics
                perms = ("R" if flags & 0x40000000 else "-") + ("W" if flags & 0x80000000 else "-") + ("X" if flags & 0x20000000 else "-")
                result["sections"].append(region(data, s.Name.rstrip(b"\0").decode("utf8", "replace"), s.PointerToRawData, s.SizeOfRawData, perms, address=s.VirtualAddress))
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                library = entry.dll.decode("utf8", "replace")
                for imp in entry.imports:
                    result["imports"].append(library + "!" + (imp.name.decode("utf8", "replace") if imp.name else f"ordinal:{imp.ordinal}"))
                    if len(result["imports"]) >= 200:
                        break
                if len(result["imports"]) >= 200:
                    break
            exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
            if exports:
                result["exports"] = [x.name.decode("utf8", "replace") for x in exports.symbols[:100] if x.name]
            resources = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
            if resources:
                for entry in resources.entries[:60]:
                    result["resources"].append(str(entry.name) if entry.name else pefile.RESOURCE_TYPE.get(entry.id, str(entry.id)))
            overlay_start = pe.get_overlay_data_start_offset()
            if overlay_start is not None:
                result["trailing"] = region(data, "PE overlay (may include legitimate certificates or installer data)", overlay_start, len(data) - overlay_start, kind="trailing")
            result["warnings"] = pe.get_warnings()[:20]
            # A suffix never determines the detected format.
            suffix = Path(filename).suffix.lower()
            if suffix and suffix not in {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".efi", ".pyd"}:
                result["warnings"].append("The extension does not normally identify a PE file; contents were used instead.")
            pe.close()
        except Exception as exc:
            result["warnings"].append(f"MZ signature found, but PE parsing failed: {type(exc).__name__}")
    elif data.startswith(b"\x7fELF"):
        try:
            elf = ELFFile(io.BytesIO(data))
            if elf.num_sections() > 4096 or elf.num_segments() > 4096:
                raise ValueError("Too many ELF regions to inspect")
            has_interpreter = any(s["p_type"] == "PT_INTERP" for s in elf.iter_segments())
            sections = list(elf.iter_sections())
            module = elf["e_type"] == "ET_REL" and any(s.name == ".modinfo" for s in sections)
            category = "Linux kernel module (.ko)" if module else "Linux shared library (.so)" if elf["e_type"] == "ET_DYN" and not has_interpreter else "Linux executable (ELF)" if elf["e_type"] in {"ET_EXEC", "ET_DYN"} else "ELF relocatable object"
            result.update(format="ELF", architecture=f"{elf['e_machine']} / {elf.elfclass}-bit", category=category,
                          entry_point=hex(elf["e_entry"]), supported=True)
            end = max(elf["e_ehsize"], elf["e_shoff"] + elf["e_shentsize"] * elf.num_sections(), elf["e_phoff"] + elf["e_phentsize"] * elf.num_segments())
            for s in sections:
                flags = s["sh_flags"]
                perms = ("R" if flags & 2 else "-") + ("W" if flags & 1 else "-") + ("X" if flags & 4 else "-")
                nobits = s["sh_type"] == "SHT_NOBITS"
                r = region(data, s.name or "(unnamed)", s["sh_offset"], 0 if nobits else s["sh_size"], perms, address=s["sh_addr"])
                r["memory_size"] = int(s["sh_size"])
                r["no_file_bytes"] = nobits
                result["sections"].append(r)
                if not nobits:
                    end = max(end, s["sh_offset"] + s["sh_size"])
                if s["sh_type"] == "SHT_DYNSYM":
                    for symbol in s.iter_symbols():
                        if symbol.name and symbol["st_shndx"] == "SHN_UNDEF" and len(result["imports"]) < 200:
                            result["imports"].append(symbol.name)
                        elif symbol.name and len(result["exports"]) < 100:
                            result["exports"].append(symbol.name)
                if s["sh_type"] == "SHT_DYNAMIC":
                    for tag in s.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED" and len(result["imports"]) < 200:
                            result["imports"].append("library:" + tag.needed)
            for s in elf.iter_segments():
                flags = s["p_flags"]
                perms = ("R" if flags & 4 else "-") + ("W" if flags & 2 else "-") + ("X" if flags & 1 else "-")
                result["segments"].append(region(data, s["p_type"], s["p_offset"], s["p_filesz"], perms, kind="segment", address=s["p_vaddr"]))
                end = max(end, s["p_offset"] + s["p_filesz"])
            if end < len(data):
                result["trailing"] = region(data, "Bytes beyond ELF declared regions", end, len(data) - end, kind="trailing")
            if not sections:
                result["warnings"].append("No section table; segment information is used where available.")
            if end > len(data):
                result["warnings"].append("One or more ELF structures refer beyond the end of the file.")
        except Exception as exc:
            result["warnings"].append(f"ELF signature found, but parsing failed: {type(exc).__name__}")
            result["supported"] = False
    return result


def byte_views(data):
    # Up to 256 windows, covering the entire file, including the final byte.
    edges = np.linspace(0, len(data), min(256, len(data)) + 1, dtype=int)
    windows = [dict(offset=int(a), size=int(b-a), entropy=entropy(data[a:b])) for a, b in zip(edges[:-1], edges[1:])]
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    # Area-average consecutive byte ranges for the overview. Explicitly not an AI heatmap.
    pixels = min(65536, len(data))
    boundaries = np.linspace(0, len(data), pixels + 1, dtype=np.int64)
    a = np.frombuffer(data, dtype=np.uint8)
    sums = np.concatenate(([0], np.cumsum(a, dtype=np.uint64)))
    image_bytes = ((sums[boundaries[1:]] - sums[boundaries[:-1]]) / np.diff(boundaries)).astype(np.uint8)
    return dict(entropy_windows=windows, histogram=counts.tolist(),
                byte_image=dict(width=min(256, pixels), pixels=base64.b64encode(image_bytes.tobytes()).decode(), count=pixels,
                                method="Consecutive bytes, averaged into at most 65,536 grayscale pixels; not malware localization."))


def observations(data, structure):
    findings = []
    for r in structure["sections"]:
        if "W" in r["permissions"] and "X" in r["permissions"]:
            findings.append(dict(title="Writable and executable section", detail=f"{r['name']} permits writing and execution. This is an indicator to investigate, not proof of malware.", offset=r["offset"]))
        if r["entropy"] >= 7.2 and r["size"] >= 1024:
            findings.append(dict(title="High-entropy section", detail=f"{r['name']} has entropy {r['entropy']:.2f}/8. Compression, encryption and legitimate packed software can cause this.", offset=r["offset"]))
        if r["out_of_bounds"]:
            findings.append(dict(title="Region extends past file", detail=f"{r['name']} declares bytes outside the uploaded file.", offset=r["offset"]))
    if structure["trailing"]:
        r = structure["trailing"]
        findings.append(dict(title="Appended bytes", detail=f"{r['size']:,} bytes at offset {r['offset']:,}. Appended content can be legitimate; it is not automatically hidden malware.", offset=r["offset"]))
    signatures = [(b"\x7fELF", "ELF"), (b"\x89PNG\r\n\x1a\n", "PNG"), (b"PK\x03\x04", "ZIP"), (b"%PDF-", "PDF"), (b"\xff\xd8\xff", "JPEG")]
    embedded = []
    for magic, label in signatures:
        start = 1
        for _ in range(8):
            offset = data.find(magic, start)
            if offset < 0:
                break
            embedded.append(dict(type=label, offset=offset, note="Signature match only; content not extracted or validated."))
            start = offset + len(magic)
    strings = []
    for m in re.finditer(rb"[\x20-\x7e]{6,160}", data):
        if len(strings) >= 100:
            break
        strings.append(dict(offset=m.start(), text=m.group().decode("ascii")))
    return findings[:40], embedded, strings


def feature_metadata(extractor):
    """Names follow upstream vector ordering, including hashed bucket caveats."""
    items = []
    general = ["File size (bytes)", "Whole-file entropy", "PE format indicator", "First byte", "Second byte", "Third byte", "Fourth byte"]
    section_general = ["Section count", "Zero-size sections", "Unnamed sections", "Readable executable sections", "Writable sections", "Maximum region entropy", "Minimum region entropy", "Maximum raw-size ratio", "Minimum raw-size ratio", "Maximum raw/virtual ratio", "Minimum raw/virtual ratio"]
    for fe in extractor.features:
        group = GROUP_LABELS.get(fe.name, fe.name)
        for j in range(fe.dim):
            name = f"{group} · feature {j}"
            if fe.name == "general":
                name = general[j]
            elif fe.name == "histogram":
                name = f"Frequency of byte 0x{j:02X}"
            elif fe.name == "byteentropy":
                name = f"Byte/entropy bin {j // 16}:{j % 16}"
            elif fe.name == "strings":
                if j < 3:
                    name = ["Printable string count", "Average string length", "Printable byte count"][j]
                elif j < 99:
                    name = f"Printable character frequency 0x{j - 3 + 32:02X}"
                elif j == 99:
                    name = "Printable-character entropy"
                else:
                    reverse = {idx: key for key, idx in fe.regex_idxs.items()}
                    name = f"String pattern count: {reverse.get(j-100, j-100)}"
            elif fe.name == "section":
                if j < 11:
                    name = section_general[j]
                elif j >= fe.dim - 3:
                    name = ["PE overlay size", "PE overlay size ratio", "PE overlay entropy"][j - (fe.dim - 3)]
                else:
                    name = f"Section hash bucket {j-11} (may combine names)"
            elif fe.name in {"imports", "exports", "richheader"}:
                name = f"{group} bucket {j} (may combine entries)"
            items.append(dict(index=len(items), name=name, group=group))
    return items


def tree_path(tree, vector, names):
    steps = []
    node = tree
    while "split_feature" in node:
        i = node["split_feature"]
        value = float(vector[i])
        threshold = node["threshold"]
        operator = node["decision_type"]
        if math.isnan(value) or (node.get("missing_type") == "Zero" and value == 0):
            left = node.get("default_left", True)
        elif operator == "==":
            left = int(value) in {int(x) for x in str(threshold).split("||")}
        else:
            left = value <= float(threshold)
        steps.append(dict(feature=names[i]["name"], index=i, value=value, operator=operator,
                          threshold=threshold, branch="left" if left else "right"))
        node = node["left_child"] if left else node["right_child"]
    return dict(steps=steps, leaf_value=node["leaf_value"], leaf_index=node["leaf_index"])


def predict(data, fmt, variant="pretrained"):
    if variant not in {"pretrained", "student"}:
        raise ValueError("Unknown model choice")
    if variant == "student" and fmt != "ELF":
        return dict(available=False, error="Our trained comparison model supports ELF files only. Choose the research model for Windows PE files.")
    model_name = "ELF_student.model" if variant == "student" else f"EMBER2024_{fmt}.model"
    model_path = ROOT / "models" / model_name
    if not model_path.exists():
        return dict(available=False, error="Model file is missing. Run the model download script.")
    extractor = PEFeatureExtractor()
    raw = extractor.raw_features(data)
    vector = extractor.process_raw_features(raw)
    if not np.isfinite(vector).all():
        raise ValueError("Feature extractor returned non-finite values")
    model = lgb.Booster(model_file=str(model_path))
    if model.num_feature() != len(vector):
        raise ValueError("Model and extractor feature counts do not match")
    score = float(model.predict(vector.reshape(1, -1), num_threads=2)[0])
    raw_score = float(model.predict(vector.reshape(1, -1), raw_score=True, num_threads=2)[0])
    contributions = model.predict(vector.reshape(1, -1), pred_contrib=True, num_threads=2)[0]
    if not np.isclose(contributions.sum(), raw_score, atol=1e-5):
        raise ValueError("Explanation contributions do not reconstruct the model score")
    names = feature_metadata(extractor)
    groups = {}
    features = []
    for meta, value, contribution in zip(names, vector, contributions[:-1]):
        groups[meta["group"]] = groups.get(meta["group"], 0.0) + float(contribution)
        features.append(dict(**meta, value=float(value), contribution=float(contribution)))
    top = sorted(features, key=lambda x: abs(x["contribution"]), reverse=True)[:12]
    verdict = "likely_malicious" if score >= 0.8 else "likely_benign" if score <= 0.2 else "uncertain"
    positive = sorted((x for x in features if x["contribution"] > 0), key=lambda x: x["contribution"], reverse=True)[:3]
    negative = sorted((x for x in features if x["contribution"] < 0), key=lambda x: x["contribution"])[:3]
    summary = f"The {fmt} model returned a score of {score:.4g}. "
    if positive:
        summary += "Features pushing toward malicious include " + ", ".join(x["name"] for x in positive) + ". "
    if negative:
        summary += "Features pushing toward benign include " + ", ".join(x["name"] for x in negative) + ". "
    summary += "This explains the model's calculation, not the program's proven behavior."
    dump = model.dump_model(num_iteration=1)
    return dict(available=True, verdict=verdict, score=score, raw_score=raw_score,
                baseline=float(contributions[-1]), contribution_sum=float(contributions[:-1].sum()),
                thresholds=dict(benign_max=0.2, malicious_min=0.8, note="Demo thresholds, not calibrated confidence limits."),
                model=model_name, dataset="EMBER2024", provenance="Our CPU-trained comparison classifier" if variant == "student" else "Public pretrained research classifier",
                source="https://github.com/FutureComputing4AI/EMBER2024", features=len(vector), trees=model.num_trees(),
                summary=summary, top_features=top,
                groups=sorted([dict(name=k, contribution=v) for k, v in groups.items()], key=lambda x: abs(x["contribution"]), reverse=True),
                first_tree=tree_path(dump["tree_info"][0]["tree_structure"], vector, names),
                caveats=["Score is not a calibrated probability that this file is malware.",
                         "Hashed features can combine multiple names and must not be attributed to a specific function.",
                         "ELF model uses general, byte and string features; ELF structure shown separately is not an ELF structural model explanation.",
                         "Driver and kernel-module accuracy has not been separately established."])


def analyze(data: bytes, filename: str, variant="pretrained") -> dict:
    started = time.perf_counter()
    if not data:
        raise ValueError("The file is empty.")
    if len(data) > MAX_FILE_SIZE:
        raise ValueError("Maximum file size is 20 MiB.")
    structure = inspect_structure(data, filename)
    findings, embedded, strings = observations(data, structure)
    prediction = dict(available=False, error="Malware prediction supports valid PE and ELF files only.")
    if structure["supported"]:
        try:
            prediction = predict(data, structure["format"], variant)
        except Exception as exc:
            prediction = dict(available=False, error=f"Prediction unavailable: {type(exc).__name__}: {str(exc)[:240]}")
    return dict(schema_version=1, filename=Path(filename.replace("\\", "/")).name[:240],
                size=len(data), sha256=hashlib.sha256(data).hexdigest(), entropy=entropy(data),
                structure=structure, prediction=prediction, findings=findings,
                embedded_signatures=embedded, strings=strings, visuals=byte_views(data),
                elapsed_seconds=round(time.perf_counter() - started, 3),
                analysis_method="Static analysis only; uploaded files are not executed or retained.",
                limitations=["Static classification can miss malware and can flag benign files.",
                             "Byte images and entropy plots do not locate malware or prove steganography.",
                             "Embedded signatures are clues, not proof of a complete embedded file."])
