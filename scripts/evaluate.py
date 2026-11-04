"""Reproducible ELF training/evaluation using features, not executable malware.

Official train/test chronology is retained. Last ~20% of training weeks form
validation; neither model is fitted on the test split. Threshold is fixed at .5.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile

import lightgbm as lgb
import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, roc_auc_score
from thrember.features import PEFeatureExtractor

ROOT = Path(__file__).resolve().parents[1]
MODEL_REV = "e5b945dd90e1a1a1ec0cc07b3a17b52e9ba2d0c2"


def download(url, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        print(f"Downloading {path.name} (labeled features only)", flush=True)
        urllib.request.urlretrieve(url, path.with_suffix(".part"))
        path.with_suffix(".part").replace(path)


def load_zip(path, extractor):
    vectors, labels, hashes, weeks = [], [], [], []
    seen = {}
    duplicates = 0
    with ZipFile(path) as z:
        files = sorted(x for x in z.namelist() if x.endswith(".jsonl"))
        for i, name in enumerate(files):
            with z.open(name) as f:
                for line in f:
                    raw = json.loads(line)
                    if raw["label"] not in [0, 1]:
                        continue
                    sha = raw["sha256"]
                    if sha in seen:
                        if seen[sha] != raw["label"]:
                            raise ValueError(f"Conflicting duplicate labels for {sha}")
                        duplicates += 1
                        continue
                    seen[sha] = raw["label"]
                    vectors.append(extractor.process_raw_features(raw))
                    labels.append(raw["label"])
                    hashes.append(sha)
                    weeks.append(i)
            if (i + 1) % 12 == 0:
                print(f"{path.name}: processed {i+1}/{len(files)} weeks", flush=True)
    return np.asarray(vectors, dtype=np.float32), np.asarray(labels, dtype=np.int8), np.asarray(hashes), np.asarray(weeks), duplicates


def metrics(name, model, x, y, description):
    scores = model.predict(x, num_threads=2)
    pred = scores >= .5
    tn, fp, fn, tp = [int(v) for v in confusion_matrix(y, pred, labels=[0, 1]).ravel()]
    decided = (scores <= .2) | (scores >= .8)
    return dict(name=name, description=description, accuracy=float(accuracy_score(y, pred)),
                precision=float(precision_score(y, pred, zero_division=0)), recall=float(recall_score(y, pred, zero_division=0)),
                false_positive_rate=fp / max(tn + fp, 1), roc_auc=float(roc_auc_score(y, scores)),
                tn=tn, fp=fp, fn=fn, tp=tp,
                app_thresholds=dict(benign_max=.2, malicious_min=.8,
                    uncertain_count=int((~decided).sum()), decision_coverage=float(decided.mean()),
                    benign_labeled_malicious=int(((y == 0) & (scores >= .8)).sum()),
                    malware_labeled_benign=int(((y == 1) & (scores <= .2)).sum())))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data")
    parser.add_argument("--download", action="store_true")
    args = parser.parse_args()
    for directory in [ROOT / "models", ROOT / "reports", args.data_dir]:
        directory.mkdir(parents=True, exist_ok=True)
    if args.download:
        for split in ["train", "test"]:
            download(f"https://huggingface.co/datasets/joyce8/EMBER2024/resolve/main/ELF_{split}.zip", args.data_dir / f"ELF_{split}.zip")
        download(f"https://huggingface.co/joyce8/EMBER2024-benchmark-models/resolve/{MODEL_REV}/EMBER2024_ELF.model", ROOT / "models" / "EMBER2024_ELF.model")
    extractor = PEFeatureExtractor()
    print("Vectorizing training features…", flush=True)
    x, y, hashes, weeks, train_dup = load_zip(args.data_dir / "ELF_train.zip", extractor)
    print("Vectorizing test features…", flush=True)
    xt, yt, test_hashes, _, test_dup = load_zip(args.data_dir / "ELF_test.zip", extractor)
    # Exclude test overlap from our own training; do not quietly change the public test population.
    overlap = np.isin(hashes, test_hashes)
    x, y, weeks = x[~overlap], y[~overlap], weeks[~overlap]
    cutoff = int(np.quantile(weeks, .8))
    train = weeks < cutoff
    val = ~train
    if set(np.unique(y[train])) != {0, 1} or set(np.unique(y[val])) != {0, 1}:
        raise ValueError("Training and validation each need both labels")
    params = dict(objective="binary", metric="binary_logloss", learning_rate=.05, num_leaves=31,
                  min_data_in_leaf=30, feature_fraction=.9, bagging_fraction=.9, bagging_freq=1,
                  num_threads=2, seed=42, deterministic=True, force_col_wise=True, verbosity=-1)
    train_set = lgb.Dataset(x[train], label=y[train])
    valid_set = lgb.Dataset(x[val], label=y[val], reference=train_set)
    print(f"Training on {train.sum():,} examples; validating on {val.sum():,}; testing on {len(yt):,}", flush=True)
    started = time.perf_counter()
    student = lgb.train(params, train_set, num_boost_round=400, valid_sets=[valid_set],
                        callbacks=[lgb.early_stopping(30, verbose=False), lgb.log_evaluation(100)])
    training_seconds = time.perf_counter() - started
    student.save_model(str(ROOT / "models" / "ELF_student.model"))
    print("Evaluating public pretrained model…", flush=True)
    pretrained = lgb.Booster(model_file=str(ROOT / "models" / "EMBER2024_ELF.model"))
    baseline = metrics("Public pretrained ELF model (used by app)", pretrained, xt, yt,
                       "Published EMBER2024 classifier, evaluated on the official later test split.")
    own = metrics("Our CPU-trained ELF model (comparison)", student, xt, yt,
                  "Trained from scratch on earlier training weeks; early stopping uses later training weeks, never the test split.")
    own.update(training_samples=int(train.sum()), validation_samples=int(val.sum()), training_seconds=round(training_seconds, 3), trees=student.num_trees())
    artifact_hashes = {f"ELF_{split}.zip": hashlib.sha256((args.data_dir / f"ELF_{split}.zip").read_bytes()).hexdigest() for split in ["train", "test"]}
    result = dict(title="Measured Linux ELF results", dataset="EMBER2024 / official ELF temporal split",
                  description="Both classifiers are evaluated on the same later, labeled test examples. These metrics use a 0.5 decision threshold; the app also has an uncertain range.",
                  evaluated_at=datetime.now(timezone.utc).isoformat(), threshold=.5,
                  test_samples=len(yt), test_benign=int((yt == 0).sum()), test_malicious=int((yt == 1).sum()),
                  train_duplicates_removed=train_dup, test_duplicates_removed=test_dup, training_test_overlap_removed=int(overlap.sum()),
                  features=extractor.dim, student_training_parameters=params, source_archives_sha256=artifact_hashes,
                  pretrained_revision=MODEL_REV, models=[baseline, own],
                  limitations="Linux ELF benchmark only. Windows predictions have integration checks, but no Windows benchmark was run in this experiment. Drivers and kernel modules were not evaluated separately. Benchmark labels may be imperfect; results do not guarantee performance on future files or new malware families. The public pretrained model's original training is trusted as documented by its authors.")
    path = ROOT / "reports" / "evaluation.json"
    path.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)
    print(f"Saved {path}", flush=True)


if __name__ == "__main__":
    main()
