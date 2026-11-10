# Research methodology and academic evaluation

## Research title
**PhishGuard: An Explainable Multi-Layer Framework for Phishing Email Detection, Digital Forensics and Incident Triage**

## Research objectives
1. Extract structured evidence from RFC 5322/MIME email messages.
2. Detect phishing indicators through deterministic rules and lexical/structural feature engineering.
3. Compare classical supervised text classifiers independently of hosted LLM services.
4. Fuse deterministic risk and calibrated ML scores only when a local model has been trained.
5. Explain each finding and support analyst case management, IOC correlation and employee feedback.

## Independent analysis arms
- **Rules-only:** six-dimension evidence scoring; all signals and weights are exposed.
- **Text-only ML:** word/character TF-IDF with Logistic Regression, calibrated Linear SVM and calibrated Random Forest.
- **Hybrid:** 65% deterministic risk index + 35% calibrated phishing score, enabled only when a local artifact exists. The fused output is still a risk index, not a probability.
- **LLM optional:** not used for verdicts. If added in future, evaluate only explanation/coaching quality, latency, cost and prompt-injection resilience.

## Data collection and governance
The project does not redistribute third-party email corpora. Acquire source data under the relevant terms and maintain the source/licence manifest. Suggested corpora to evaluate include Enron (legitimate corporate email) and SpamAssassin public corpus (ham/spam), plus current phishing URL feeds as indicator enrichment rather than as substitutes for labelled email messages. Phishing email datasets from academic repositories may be used only after verifying licence, provenance and label semantics. Do not upload private email to public services or commit personal mailboxes.

Recommended target: start with 5,000–10,000 labelled messages across multiple campaigns and source domains; stretch target 20,000–50,000. These are research targets, not a claim about the data currently included. Record collection period, language, source, label, campaign/thread group, license, message hash, and whether synthetic. Keep raw email in controlled storage and use the included builder to redact email addresses, phone-like strings and URLs from text-model features.

## Leakage prevention
Exact duplicates are removed. The dataset schema requires `group_id` for campaigns, threads, sender clusters or near-duplicate families. The default split groups messages before chronological train/validation/test partitioning so groups do not cross partitions. The user must assign meaningful campaign groups; the code cannot infer all campaign relationships from raw text alone. Do not use random row-level splitting as the headline result.

## Metrics
Report per-class precision/recall/F1, macro-F1, confusion matrix, false-positive rate, ROC-AUC, PR-AUC, Brier score, fit time and per-email inference latency. Add bootstrap confidence intervals for headline metrics in the final dissertation analysis. Compare all models on the same held-out partition. Preserve the `evaluation.json` artifact, dataset manifest, random seed and code version.

## Required experiments
1. Rules-only vs text-only ML vs hybrid.
2. Logistic Regression vs Linear SVM vs Random Forest.
3. Subject-only vs body-only vs combined text ablation.
4. Remove URL evidence; remove authentication evidence; remove attachment evidence.
5. LLM disabled and internet unavailable.
6. Missing/malformed Authentication-Results, HTML-only email, nested MIME, duplicate From, Reply-To mismatch, IDN/punycode, archive attachments, misleading extension.
7. False-positive analysis across legitimate newsletters, bulk senders, forwarded messages and internal mail.
8. Time/campaign split compared with random split (random split is a leakage diagnostic only).

## Limitations to state honestly
- Receiver-stamped SPF/DKIM/DMARC observations are not cryptographic verification performed by this system.
- The six-dimension rule score is an expert-authored heuristic index until empirically calibrated.
- Similar-domain detection is a lexical lead, not a brand-abuse verdict.
- A reputation feed returning no match does not establish safety.
- Synthetic smoke examples test the software pipeline only and must not be included in real-world performance claims.
- Generalization depends on source coverage, languages, evolving attacker behaviour, labels and drift.
- Automated analysis does not authorize deleting mail, blocking infrastructure or quarantining accounts.

## Reproducibility checklist
- [ ] Dataset sources and licence reviewed
- [ ] Labels manually quality-checked
- [ ] PII redacted from training export
- [ ] Exact and near-duplicate groups reviewed
- [ ] Campaign/time holdout locked before model selection
- [ ] Same test set used for all models
- [ ] Metrics, confidence intervals, latency and false positives reported
- [ ] Synthetic rows excluded from headline metrics
- [ ] Model artifact, evaluation JSON and environment versions archived
