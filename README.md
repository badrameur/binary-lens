# Binary Lens

A working, explainable static malware classifier for Windows PE and Linux ELF
files. Built as a school project with Python, LightGBM and a plain JavaScript
interface. Training and inference use the CPU; Gemini and a GPU are not required.

## Start on Linux (x86_64)

On a fresh clone, install the local environment, then start the server:

```bash
bash setup.sh
bash run.sh
```

Open **http://127.0.0.1:8000**. Use `PORT=8001 bash run.sh` if port 8000 is occupied.
The service binds to loopback only. Ctrl+C stops a server started in your terminal.

Choose a file, choose a classifier, and click **Analyze file**. The built-in Linux
demo inspects a copy of `/usr/bin/true`; it does not execute it. The comparison
model is available under **Our CPU-trained model · Linux only**. JSON reports are
downloaded to the browser, not stored on the server.

On another Linux x86_64 computer, extract the project and run `bash setup.sh`
first. This downloads a project-local Python 3.12 interpreter and installs locked
dependencies without changing system Python. It also downloads the public PE/ELF
models and prepares the benign demo. The trained comparison model and evaluation
results are included in the school-project archive.

Manual installation on other systems requires Python 3.12, dependencies from
`requirements.lock.txt`, and the vendored EMBER2024 package. The worker uses Linux
`resource` limits, so running the server itself on Windows requires adaptation
(or WSL). **Analyzing Windows files on Linux is fully supported.**

## What works

- Identify PE and ELF by parsed contents rather than trusting extensions.
- Inspect EXE, DLL, SYS, ELF executables, SO, and KO categories. These are six
  categories within two main formats, not six unrelated file formats.
- Calculate malware scores using the corresponding public EMBER2024 LightGBM
  model, or our own trained ELF comparison model.
- Explain actual predictions with LightGBM's SHAP feature contributions, grouped
  contributions, the score reconstruction equation, and a real path through the
  first decision tree.
- Inspect sections, ELF segments, permissions, entropy, imports, exports,
  resource types, appended content, parser warnings, and readable strings.
- Display a grayscale byte overview, full-file entropy windows and byte histogram.
- Show measured evaluation results and export a complete JSON analysis.

## Architecture

```text
static/index.html + app.js + style.css
                ↓ multipart upload
app.py: FastAPI, upload limits, one active worker
                ↓ bytes through stdin
worker.py: separate process, CPU/memory/wall-time limits
                ↓
analyzer.py
  ├─ pefile / pyelftools → structural observations
  ├─ original thrember extractor → 2,568 features
  ├─ PE or ELF LightGBM model → score
  └─ actual feature contributions + tree path → explanation
                ↓
JSON → interactive interface / optional browser export
```

`scripts/evaluate.py` and the Colab notebook handle training separately. See
`PRESENTATION_GUIDE.md` for the method, measured results, presentation script and
questions a teacher may ask.

## Model explanation

The fixed vector contains file information, normalized byte frequencies, local
byte/entropy statistics, string statistics and PE features. ELF files use the
general byte and string features; PE-specific groups are zero-filled by the
upstream extractor. ELF sections shown by the UI are **observations**, not ELF
structural inputs used by this model.

Each LightGBM tree compares measured features against learned thresholds. The
ensemble produces a raw score; the binary sigmoid produces the displayed model
score. The score is **not calibrated certainty that a file is malware**.

LightGBM's `pred_contrib=True` returns feature contributions and a baseline. The
analyzer verifies that their sum reconstructs the raw score. Contributions are
in log-odds, not probability percentage points. Hashed buckets may combine
multiple entries, so they cannot identify a specific imported API as the cause.

Default app decision bands are fixed at ≤ 0.2 likely benign, ≥ 0.8 likely
malicious, and uncertain in between. The evaluation's main precision/recall and
confusion matrix use a fixed **0.5** threshold for a conventional binary
comparison. The JSON also includes counts for the app's abstaining decision bands.

## Train and evaluate

Linux feature archives are present under `data/` on the original computer. They
contain numerical features and labels, **not executable malware**.

```bash
OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=1 .venv/bin/python scripts/evaluate.py
```

On a fresh copy, add `--download` to fetch the ELF feature archives and pretrained
ELF model. The notebook `notebooks/Binary_Lens_Colab.ipynb` performs the same
experiment in Colab with no GPU. Its syntax and generated training script were
checked locally; this session's actual training ran on this PC, not in a logged-in
Colab session.

The experiment deduplicates SHA-256 hashes, retains the official temporal
train/test split, reserves later training weeks for validation, removes any
test overlap from our training and never chooses hyperparameters using test
scores. It saves `models/ELF_student.model` and `reports/evaluation.json`.

The UI uses the pretrained model by default because its measured Linux test
performance is better in this experiment. Our model can still be selected and
used to analyze actual ELF uploads.

To continue training an existing model, LightGBM supports `init_model` with
compatible feature definitions. It adds boosting trees; it is not an automatic
quality improvement. The included experiment deliberately trains from scratch
to make our learning process and validation easier to explain.

## Checks

```bash
OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=1 .venv/bin/python -m pytest -q
node --check static/app.js
```

Tests cover PE32/PE64 and Windows categories, Linux categories, real predictions,
score reconstruction, full-byte visual coverage, appended-content observations,
unsupported/malformed files, request limits and real worker uploads. API tests
need normal local thread/process communication; an execution sandbox that blocks
event-loop cross-thread communication can prevent TestClient from completing.

Final check: **18 tests passed**. The browser demo, trained-model selection,
explanation and byte charts were exercised. Browser automation could not select
a local file because the connected extension's file-access permission was off;
no browser permissions were changed. Harmless 32-bit and 64-bit Windows samples
were also checked through the local HTTP API. The normal file chooser remains
available for manual use.

## Limits and honest claims

This is a school research classifier, not a production antivirus or a hardened
malware sandbox. Uploaded files are never intentionally executed. The parser
worker has a 20 MiB file limit, 2 GiB address-space limit, 45 second CPU limit and
60 second wall timeout. Multipart spooling may temporarily use disk while a file
is being received; closing the upload deletes that temporary data. Results are
not retained by the API.

Models can miss malware and flag harmless programs. Our local `hello.c`, compiled
with GCC at `-O2`, was one observed false positive for the public model on this
machine (score approximately 0.815). It remains included as an honest demonstration
of model limitations. A separate copy of the system's benign `true` program is
the default demo. Compiled output and scores may differ on another machine.

The measured benchmark covers **Linux ELF only**. No Windows detection-accuracy
benchmark was run. Windows parsing/inference have integration checks. Accuracy
for drivers and kernel modules was not evaluated separately. Valid digital
signature metadata, high entropy, appended bytes or embedded file signatures
alone do not establish malware. The app does not unpack, emulate, dynamically
execute files or reliably discover arbitrary steganography.

## Provenance

- Dataset and extractor: https://github.com/FutureComputing4AI/EMBER2024
- Vendored source commit: `0ef753e` (Apache 2.0 license retained).
- Models: https://huggingface.co/joyce8/EMBER2024-benchmark-models
- Model revision: `e5b945dd90e1a1a1ec0cc07b3a17b52e9ba2d0c2`.
- Model checksums and sources: `models/manifest.json`.
- Exact test archive checksums, parameters and metrics: `reports/evaluation.json`.
- LightGBM explanations: https://lightgbm.readthedocs.io/en/stable/pythonapi/lightgbm.Booster.html

The PE and ELF research models are pretrained public artifacts, not models we
claim to have originally created. Our separately trained artifact is explicitly
named `ELF_student.model`. Windows launcher samples, when present, come from the
distlib launchers bundled in Python's pip wheel; their license is retained under
`samples/DISTLIB_LICENSE.txt`. The system `true` binary is prepared locally and
excluded from the portable source archive.
