# Feature matrix — PhishGuard 2.0

| Capability | Status | Notes / boundary |
|---|---|---|
| RFC/MIME email parsing | Implemented | Plain/HTML body, headers, Received chain, Message-ID, sender fields |
| Authentication observations | Implemented | Reads receiver-stamped SPF/DKIM/DMARC headers; not independent DNS or DKIM cryptographic verification |
| Header identity analysis | Implemented | From/Reply-To/Return-Path mismatch, multiple From, selected display-name mismatch |
| URL intelligence | Implemented | Passive lexical features, punycode, IP literals, entropy, shorteners, brand similarity; no automatic URL fetch |
| Attachment forensics | Implemented | SHA-256, magic bytes, extension/MIME mismatch, archive listing, risky file types |
| YARA / ClamAV | Optional | YARA requires `yara-python` and rules; ClamAV requires system `clamscan` executable |
| QR extraction | Optional | Pillow + pyzbar + system zbar dependency; extracted URL is not fetched |
| Six-dimension risk index | Implemented | Transparent weighted heuristic score; not a probability or calibrated threshold |
| Local ML comparison | Implemented | TF-IDF Logistic Regression, calibrated Linear SVM and Random Forest; user supplies labelled data |
| ML evaluation | Implemented | Validation-only model selection, untouched final test, class metrics, ROC/PR-AUC, Brier, FPR, latency and group bootstrap interval |
| Dataset preparation | Implemented | `.eml` manifest builder, PII redaction, exact dedupe, near-duplicate grouping and quality report |
| Dashboard and investigations | Implemented | Vanilla JS + Chart.js, filters, detail evidence view |
| PDF forensic report | Implemented | ReportLab; SHA-256 is an integrity aid, not legal chain-of-custody proof |
| Incident case workflow | Implemented | Open/investigating/contained/resolved/false-positive, assignee and notes |
| IOC register | Implemented | Extracts domains, URLs and attachment hashes |
| External threat intelligence | Optional live integration | VirusTotal domain and URLhaus URL lookup; explicit consent required; no-hit is not proof of safety |
| Employee awareness feedback | Implemented | Stores pseudonymous reporting/training outcomes; requires consent and data governance |
| API role controls | Implemented for API | Viewer/analyst/admin API-key roles; local mode defaults to single-user admin; no enterprise SSO |
| Audit log | Implemented for selected actions | Analysis, incident and training actions; not a tamper-proof forensic ledger |
| Redirect-chain resolution | Not implemented | Deliberately omitted until isolated SSRF-safe egress worker exists |
| Live quarantine / mailbox deletion | Not implemented | No mail-provider integration; no destructive actions |
| Enterprise SSO / multi-tenant RBAC | Not implemented | Prototype requires production identity, isolation and deployment hardening |
| Production-grade retention / immutable evidence vault | Not implemented | Configure retention and protected storage before real organisational use |

Optional tools and external APIs are not required for core analysis. See `README.md`, `docs/THREAT_MODEL.md` and `docs/ACADEMIC_EVALUATION_PROTOCOL.md`.
