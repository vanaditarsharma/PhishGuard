# Final-year project report guide

Use this as the structure for the dissertation/report. Replace every bracketed instruction with your own verified details, screenshots and measured results. Do not copy synthetic smoke-test metrics into the results chapter.

1. **Title page** — PhishGuard 2.0; student name, registration number, programme, department, institution, supervisor and academic year.
2. **Abstract** — problem, research gap, method, dataset size/source, evaluation protocol and actual measured headline results (only after experiments).
3. **Introduction** — phishing context, motivation, objectives, scope and contributions.
4. **Literature review** — peer-reviewed work on email authentication, phishing URL detection, NLP/text classification, explainable ML, incident response. Build a comparison matrix with year, dataset, features, algorithms, metrics and limitations. Verify every paper and citation.
5. **Problem definition and research gap** — limitations of single-signal and LLM-dependent approaches; explain the project’s deterministic, ML and hybrid evaluation arms.
6. **Requirements and threat model** — functional/non-functional requirements, trust boundaries, assets, attacker goals, privacy and safety constraints.
7. **System design** — architecture, data flow, module diagram, database schema, API design, risk dimensions and role model.
8. **Methodology** — dataset provenance, label policy, preprocessing, PII redaction, deduplication, campaign grouping, chronological split, models, validation selection, risk fusion and metrics.
9. **Implementation** — screenshots and explanation of scanner, evidence details, dashboard, incidents, IOC register, reports and awareness feedback.
10. **Experimental setup** — hardware/software versions, dependencies, random seed, dataset manifest hash, model configuration and test split description.
11. **Results and analysis** — actual model comparison, confusion matrices, per-class precision/recall/F1, FPR, ROC-AUC, PR-AUC, Brier score, latency, confidence intervals, feature ablations and false-positive case studies.
12. **Security testing** — malformed MIME, oversized upload, spoofed headers, suspicious URLs, archive/file signature cases, API role checks, privacy and external lookup consent.
13. **Discussion** — answer research questions; compare with literature only when datasets/protocols are comparable; discuss drift and external validity.
14. **Limitations and future work** — authentication verification boundary, heuristic calibration, dataset/language coverage, SSRF-safe redirect worker, mail-provider integration and production controls.
15. **Conclusion** — contributions supported by your results, not marketing claims.
16. **References and appendices** — verified references, dataset manifest, API docs, test logs, sample outputs and user guide.

## Evidence to capture for evaluation

- Screenshot: overview dashboard after multiple sample scans.
- Screenshot: one phishing investigation with authentication, URL and attachment evidence.
- Screenshot: incident created and status changed.
- Screenshot: IOC register showing domains, URLs and attachment hashes extracted from analyzed messages.
- Screenshot: PDF forensic report.
- Screenshot: research training output from your real labelled dataset.
- Attach test report, dataset quality report, model evaluation JSON and ablation JSON.

## Suggested viva demonstration order

1. Explain why the core verdict works without an LLM.
2. Upload a suspicious `.eml` and explain each evidence dimension.
3. Show how the system hashes but does not execute an attachment.
4. Show the investigation record, IOC register.
5. Create an incident and update its workflow status.
6. Explain how a labelled dataset is prepared, deduplicated and split by campaign/time.
7. Compare rules-only, text ML and hybrid results; explain FPR and why test data is held back.
8. Show the limitations and explain why a low score or threat-intel no-hit is not proof of safety.
