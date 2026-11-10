# Research methodology and evaluation plan

## Research question
Can deterministic email forensics, classical sparse-text machine learning and evidence-level explanations support phishing triage without depending on a hosted LLM?

## Experimental arms
- **A — Rules only:** six transparent evidence dimensions and a weighted 0–100 heuristic risk index.
- **B — Text ML:** word/character TF-IDF with Logistic Regression, calibrated Linear SVM and calibrated Random Forest.
- **C — Hybrid:** fixed initial 65% rules + 35% local calibrated model score when a model exists. The fused value remains a risk index, not a probability. Any alternative weights must be selected on validation data only.
- **D — Offline resilience:** no external network and no reputation provider.
- **E — Optional LLM enrichment:** future explanation/coaching comparison only; it must not become the sole source of verdicts.

## Dataset governance
Use corpora only where licence/terms permit. Keep source, collection date, original and normalized label, message hash, campaign/group ID, language, synthetic/real flag and licence in the manifest. Deduplicate exact and near-duplicate content. Keep personally identifiable information out of shared research exports. Do not redistribute raw email without permission.

## Split strategy
The trainer requires explicit group IDs, ISO dates, source and licence metadata. Exact duplicates are removed. Researchers should run the near-duplicate grouping utility and review groups before training. The default splitter is chronological and group-preserving; groups do not cross train, validation and final test. Model selection uses validation macro-F1; the chosen model is refit on train+validation and evaluated once on the untouched test set. If a partition lacks both labels, collect more independent campaigns rather than silently falling back to row-level random splitting.

## Metrics
Report per-class precision/recall/F1, macro-F1, confusion matrix, false-positive rate, ROC-AUC, PR-AUC, Brier score, fit time, inference latency, test size and independent test group count. The trainer reports campaign/group-level percentile bootstrap intervals for macro-F1. With few independent groups, intervals remain unstable. Also report model size, memory and p50/p95 latency if measured in the target deployment environment.

## Ablations and resilience
1. Rules-only vs text-ML-only vs hybrid.
2. Logistic Regression vs calibrated Linear SVM vs calibrated Random Forest.
3. Subject-only vs body-only vs combined text features.
4. Remove each evidence dimension using `scripts/evidence_ablation.py`.
5. LLM disabled and network unavailable.
6. Missing/malformed Authentication-Results, HTML-only email, duplicate From, Reply-To mismatch, IDN/punycode, URL shortener, IP-literal URL, ZIP/archive attachment and misleading extension.
7. False-positive analysis across newsletters, bulk mail, forwarded messages and internal mail.

## Limitations
Heuristic thresholds and dimension weights are expert-authored starting points, not empirically optimized or calibrated. Receiver-stamped authentication values are observations, not independent cryptographic verification. The trainer does not provide a real-world benchmark corpus; researchers must collect and licence one. Synthetic demonstration mail must never be counted as independent real-world performance evidence. See `ACADEMIC_EVALUATION_PROTOCOL.md` for the full procedure.
