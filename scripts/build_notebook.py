"""Generate a standalone Colab training notebook from our tested training script."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def cell(kind, source):
    result = {"cell_type": kind, "metadata": {}, "source": source.splitlines(keepends=True)}
    if kind == "code":
        result.update(execution_count=None, outputs=[])
    return result


def main():
    cells = [
        cell("markdown", "# Binary Lens — explainable malware classification\n\nTrain our own Linux ELF LightGBM model on public labeled features, then compare it with the public pretrained model. **CPU runtime is sufficient; do not select a GPU.** This notebook downloads feature vectors, never executable malware.\n\nThe application supports Windows PE and Linux ELF; this training experiment evaluates **ELF only**. Files are not executed. Pretrained artifacts and our trained artifact are clearly separated.\n"),
        cell("markdown", "## 1. Install dependencies\n\nRun this cell first in a fresh Colab CPU session. The feature extractor is pinned to the same upstream source commit as the app. Signify 0.7.1 preserves the API that extractor expects. If Colab requests a runtime restart after installing numerical packages, restart and continue from the next cell.\n"),
        cell("code", "%pip install -q 'signify==0.7.1' 'lightgbm>=4.6,<5' 'git+https://github.com/FutureComputing4AI/EMBER2024.git@0ef753e'\n"),
        cell("markdown", "## 2. Write the reproducible experiment\n\nThe code below is exactly the project training script. It deduplicates hashes, keeps the official temporal train/test separation, trains on earlier training weeks, and validates on later training weeks. Test examples are not used to select the model.\n"),
        cell("code", "from pathlib import Path\nproject = Path('/content/binary-lens')\n(project / 'scripts').mkdir(parents=True, exist_ok=True)\n"),
        cell("code", "%%writefile /content/binary-lens/scripts/evaluate.py\n" + (ROOT / "scripts" / "evaluate.py").read_text()),
        cell("markdown", "## 3. Download features, train and evaluate\n\nDownloads approximately 83 MiB of compressed ELF feature archives plus the ELF model. The original dataset may contain duplicate rows: they are removed by SHA-256. CPU training is small; downloading and vectorizing data can take longer. The script writes the exact counts, checksums, parameters, and confusion matrices to the report.\n"),
        cell("code", "!OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=1 POLARS_MAX_THREADS=2 python /content/binary-lens/scripts/evaluate.py --download\n"),
        cell("markdown", "## 4. Understand the results\n\nPrecision: how many flagged examples were labeled malware. Recall: how much labeled malware was found. False-positive rate: how much benign software was flagged. Main metrics use threshold **0.5**. The app uses separate **0.2 / 0.8** decision bands with an uncertain region; those counts are also recorded. Accuracy does not establish that an arbitrary future file is safe.\n"),
        cell("code", "import json\nimport pandas as pd\nreport = json.loads((project / 'reports/evaluation.json').read_text())\ndisplay(pd.DataFrame([{k: v for k, v in model.items() if k in ['name', 'accuracy', 'precision', 'recall', 'false_positive_rate', 'tn', 'fp', 'fn', 'tp']} for model in report['models']]))\nprint(report['limitations'])\n"),
        cell("markdown", "## 5. Export our work\n\nDownload the trained model and measured report. To use the model in the local application, copy `ELF_student.model` into its `models/` directory and choose **Our CPU-trained model**. Copy `evaluation.json` into `reports/` to update the evaluation page. The model file is a LightGBM text model, not a Python pickle.\n"),
        cell("code", "import zipfile\nfrom google.colab import files\noutput = Path('/content/binary-lens-training-results.zip')\nwith zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:\n    archive.write(project / 'models/ELF_student.model', 'models/ELF_student.model')\n    archive.write(project / 'reports/evaluation.json', 'reports/evaluation.json')\nfiles.download(str(output))\n"),
        cell("markdown", "## Sources and presentation notes\n\n- Dataset, extractor and training approach: https://github.com/FutureComputing4AI/EMBER2024\n- Public comparison models: https://huggingface.co/joyce8/EMBER2024-benchmark-models\n- Model inspection and feature contributions: https://lightgbm.readthedocs.io/en/stable/pythonapi/lightgbm.Booster.html\n\nA pretrained model can be inspected without retraining. LightGBM also supports continued training with `init_model`; this experiment trains our own model from scratch for a clear school demonstration. SHAP contributions explain a prediction's calculation, not causation or exact malware location.\n"),
    ]
    notebook = {"nbformat": 4, "nbformat_minor": 5, "metadata": {"colab": {"name": "Binary_Lens_Colab.ipynb"}, "kernelspec": {"name": "python3", "display_name": "Python 3"}, "language_info": {"name": "python"}}, "cells": cells}
    for i, item in enumerate(cells):
        item["id"] = f"binary-lens-{i:02d}"
    (ROOT / "notebooks" / "Binary_Lens_Colab.ipynb").write_text(json.dumps(notebook, indent=2) + "\n")


if __name__ == "__main__":
    main()
