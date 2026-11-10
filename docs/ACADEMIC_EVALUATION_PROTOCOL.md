# PhishGuard 2.0 — Academic Evaluation Protocol

This protocol is designed to prevent inflated or irreproducible claims. The downloadable package contains software, a synthetic smoke-test generator, and dataset preparation tools; it does **not** contain a large real-world labelled benchmark. Collect and licence a benchmark before claiming empirical superiority.

## Research questions

1. Does deterministic forensic evidence improve phishing triage over text-only classification?
2. How do Logistic Regression, calibrated Linear SVM and Random Forest compare on the same campaign/time-separated test set?
3. Which evidence dimensions contribute most to the hybrid risk index?
4. What is the operational trade-off between recall, false-positive rate and inference latency?
5. Does the system continue to produce a usable verdict with no external network access and no reputation API?

## Experimental arms

| Arm | Input | Method | Output |
|---|---|---|---|
| A | Headers, URLs, attachments, language and behavioural evidence | Deterministic rules | Transparent 0–100 heuristic risk index |
| B | Subject + body | TF-IDF word/character features with LR, calibrated Linear SVM, Random Forest | Calibrated text-model score |
| C | A + B | 65% rules + 35% local model when trained | Hybrid risk index, not probability |
| D | A/B/C without external services | Offline resilience test | Availability and latency |

## Dataset governance and minimum reporting

Use only data you have permission to process. Suggested starting target is 5k–10k messages with a stretch target of 20k–50k; these are targets, not bundled data or achieved counts. Record source, licence/terms, collection date, language, label policy, campaign/thread group, synthetic flag and SHA-256 message hash. Preserve a private source manifest. Remove personal identifiers from text features and do not commit raw personal mail.

A valid supervised CSV has: `subject,body,label,group_id,date,source,synthetic,license`. The trainer rejects missing date/source/licence or missing explicit group IDs. Exact duplicates are removed; run `scripts/near_duplicate_groups.py` and manually review group assignments before splitting. Groups must represent campaigns, threads, sender clusters or near-duplicate families.

## Split and model selection

The default splitter orders campaign groups chronologically, then allocates train, validation and final test partitions. No group should cross a partition. Model selection uses validation macro-F1 only. The selected model is refit on train + validation, then evaluated once on the untouched final test set. If a partition lacks both classes, collect more independent campaign groups; do not silently switch to a random row split.

## Metrics to publish

Publish the complete per-class precision, recall and F1; macro-F1; confusion matrix; phishing false-positive rate; ROC-AUC; PR-AUC; Brier score; training duration; per-email inference latency; test sample count; independent test campaign count; and campaign-level bootstrap confidence interval. Explain that a bootstrap interval with very few independent campaigns is unstable. Include software version, Python/dependency versions, seed, dataset manifest hash and model artifact hash.

## Ablations and robustness

Run subject-only/body-only/combined ablations. Separately remove URL, authentication and attachment evidence. Compare rules-only, text-only and hybrid. Test malformed and absent authentication headers, HTML-only messages, duplicate From headers, Reply-To mismatch, IDN/punycode domains, URL shorteners, IP-literal URLs, nested/ZIP attachments, misleading file extensions, malformed MIME and oversized uploads. Test LLM/API absent and external reputation consent declined.

## Statistical and ethical reporting

Do not claim the rules weights or risk bands are calibrated probabilities. Do not select the final model on the final test set. Do not use synthetic smoke-test messages in benchmark claims. Report class/source/language/campaign composition and false-positive examples. A no-hit from threat intelligence is not proof of safety. Infrastructure overlap is not proof of common attacker attribution. Human review remains necessary for consequential response actions.

## Reproduction commands

```powershell
python scripts/dataset_quality.py datasets/curated.csv
python scripts/near_duplicate_groups.py datasets/curated.csv --output datasets/grouped.csv
python scripts/train_model.py datasets/grouped.csv
python scripts/ablation_experiment.py datasets/grouped.csv
python scripts/evidence_ablation.py datasets/manifest.csv
```

The smoke-test generator is only for verifying the pipeline:

```powershell
python scripts/generate_synthetic_smoke.py
python scripts/train_model.py datasets/synthetic_smoke.csv --include-synthetic
```

Never report the smoke-test metrics as real-world performance.
