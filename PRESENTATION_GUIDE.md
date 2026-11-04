# Binary Lens — school presentation guide

## The project in one sentence

Binary Lens reads Windows and Linux binaries without executing them, predicts
whether their static features resemble malware, and explains which features
influenced the prediction.

## A four-minute demonstration

1. **Problem, 30 seconds:** file extensions do not establish safety. We want a
   low-cost way to inspect a file and obtain an explainable malware prediction.
   Our solution runs on the CPU of an ordinary laptop.
2. **Upload, 45 seconds:** open the application and use the harmless Linux demo.
   Explain the detected format, architecture, SHA-256 and malware score. A score
   is a model output, not a guarantee of safety.
3. **Explanation, 60 seconds:** open **Why this result**. Show positive and
   negative feature contributions and the baseline equation. Then show one real
   decision-tree path. Mention that the whole ensemble combines 500 trees for
   the public model; the one displayed tree is only an illustration.
4. **Inspection, 45 seconds:** open **File structure** and **Byte explorer**.
   Show sections, segments, permissions, entropy and the byte image. These views
   describe the file. They are not a reliable map of malicious instructions.
5. **Our work and results, 40 seconds:** open **Model evaluation**. We trained an
   ELF model from scratch and compared it with the public model using the same
   later test data. Select our model and analyze the demo again to show it works.
6. **Limitations, 20 seconds:** false alarms and missed malware exist. Windows
   has working inspection and inference, but this experiment measured Linux
   accuracy only. Drivers and kernel modules need separate evaluation.

## How to explain the AI

**Training:** each example is a vector of numerical features plus its label,
0 for benign or 1 for malicious. LightGBM learns many decision trees. A tree
asks questions such as whether a measured feature exceeds a learned threshold.
Later trees improve the objective based on the current ensemble's errors.

**Inference:** for a new file, we calculate the same ordered features. The model
follows branches in every tree and combines their leaf values into a raw score.
For this binary objective, a sigmoid converts the raw score into the 0–1 score.

```text
score = 1 / (1 + exp(-raw_score))

raw_score = baseline + sum(feature contributions)
```

Contributions are in **log-odds**, not probability percentage points. Positive
contributions push toward malicious; negative ones push toward benign. The
application verifies that their sum reconstructs the model's actual raw score.
Small differences in the displayed equation come from rounding.

**Explainability:** LightGBM calculates SHAP feature contributions for the actual
file. We group them into readable categories and show the strongest individual
features. A contribution explains a model calculation, not causation or proven
runtime behavior. A feature can influence the result because it is absent.

## What information is used?

The upstream feature vector has **2,568 numbers**. It includes general file
information, byte frequencies, local byte/entropy patterns, printable string
statistics, and PE-specific information such as headers, sections and imports.

For Linux ELF files, PE-only features are zero-filled. The ELF classifier uses
general file, byte and string information. Our extra ELF parser shows structural
observations, but those observations should not be presented as structural
features that the ELF classifier learned.

Some named entities are compressed into hash buckets. Different imports or
section names can share a bucket. Therefore an import bucket contribution does
not prove a specific imported function caused a decision.

## Why separate Windows and Linux models?

PE and ELF have different layouts and software distributions. We identify the
format from contents, then select the corresponding model. EXE, DLL and SYS are
categories within PE; Linux executables, SO and KO are generally ELF categories.
Inspecting a category does not establish that its detection accuracy is known.

## The experiment we actually performed

Source: EMBER2024 public ELF feature archives. No executable malware was needed.

- Training examples used by our model: **20,500**.
- Later training examples reserved for validation: **5,500**.
- Unique examples in the later official test split: **5,989**.
- Test labels: **2,989 benign**, **3,000 malicious**.
- Duplicate SHA-256 entries removed: 26,000 from training archive rows and 6,011
  from test archive rows. Counts here are unique files, not archive row counts.
- Training/test hash overlap removed from our training: **0**.
- Own model: **250 trees**, trained in approximately **29.8 seconds** on this CPU.
- Main metrics use threshold **0.5**. We did not tune it on the test set.

| Metric | Public ELF model | Our trained ELF model |
|---|---:|---:|
| Accuracy | 96.54% | 94.09% |
| Precision | 95.18% | 92.84% |
| Recall | 98.07% | 95.57% |
| False-positive rate | 4.98% | 7.39% |
| Correct benign (TN) | 2,840 | 2,768 |
| False alarms (FP) | 149 | 221 |
| Missed malware (FN) | 58 | 133 |
| Correct malware (TP) | 2,942 | 2,867 |

Our model's hyperparameters were fixed in the script. Early stopping used
validation data. The public model was evaluated as downloaded; its original
training is trusted according to its authors' documented split.

The public model performed better in this experiment, so it is the default. Our
model remains usable in the app. This is a measured comparison, not a claim that
our model improves the published one.

The app uses an uncertain range between **0.2 and 0.8**, distinct from the binary
benchmark threshold of 0.5. For the public model, 168 test examples fell into that
uncertain range. There were still 109 benign examples above 0.8 and 47 malicious
examples below 0.2. An uncertainty band does not eliminate mistakes.

All exact figures, dataset checksums and parameters are in
`reports/evaluation.json`. Benign integration checks are separately recorded in
`reports/benign_demo_checks.json`.

## An honest false-positive demonstration

The included `samples/hello.c` only prints a greeting. Compiling it with this
machine's GCC at `-O2` produced a benign ELF file that the public model scored
about **0.815**, placing it in the likely-malicious band. This is a false alarm.
Use it to show that ML detects statistical resemblance, not certainty.

The default harmless demo is a copy of the system's `true` command. It scored
about **0.000052** in our check. Harmless Windows distlib launchers scored about
**0.080** (32-bit) and **0.077** (64-bit). These few sample checks verify the
integration, not Windows accuracy. Do not present them as a representative test.

## Questions a teacher may ask

**Did you build the entire AI from zero?** We integrated published research
models and their compatible feature extractor, built the application and
explanation workflow, and trained a separate ELF model ourselves. We explicitly
identify the source and origin of each model.

**Can a pretrained model be retrained?** LightGBM can continue training from an
existing model with compatible features using `init_model`. We chose training
from scratch for the comparison because it makes our own experiment clear.
Continued training would need separate validation and might reduce accuracy.

**Why no GPU?** These are boosted decision trees over a few thousand numerical
features. CPU training and inference fit this school project's scale. Deep
learning directly over raw bytes would require different data and more work.

**Is this using Gemini?** No. Predictions and explanations work locally without
an LLM or cloud API. Explanations are derived from the actual tree model.

**Does a byte image reveal hidden malware?** No. It maps byte values to
grayscale; larger files are averaged into a small overview. Entropy and embedded
signatures are clues. They do not provide universal steganography detection or
precise malware localization.

**Can it inspect malware safely?** Uploaded code is never intentionally run.
Parsing happens in a bounded child process. This is resource isolation, not a
hardened security sandbox. The project uses labeled feature data for training
and harmless binaries for its integration demonstration.

**What are the limitations?** Dataset age and software differences, imperfect
labels, false positives, missed malware, packing and obfuscation, no dynamic
analysis, and incomplete per-category evaluation. Linux benchmark performance
does not establish Windows performance.

**What would we improve next?** Evaluate representative Windows data, measure
drivers and kernel modules separately, test more recent independent software,
calibrate scores on validation data, compare thresholds at an acceptable
false-positive rate, and improve parser isolation.

## Attribution

Joyce et al., *EMBER2024 — A Benchmark Dataset for Holistic Evaluation of
Malware Classifiers* (2025). Dataset and code:
https://github.com/FutureComputing4AI/EMBER2024

LightGBM feature contributions and tree inspection:
https://lightgbm.readthedocs.io/en/stable/pythonapi/lightgbm.Booster.html
