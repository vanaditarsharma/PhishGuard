# Security design and threat model

## Assets
Raw uploaded email bytes during request processing; extracted headers/body; attachment hashes and metadata; case notes; model artifacts; API credentials; analyst/audit records.

## Trust boundaries
Browser → FastAPI; uploaded email → parser; extracted URLs → optional external reputation provider; dataset upload → training process; API caller → role guard; attachment bytes → optional YARA/ClamAV process.

## Threats and controls
- **Malicious MIME / oversized upload:** 10 MiB configurable upload limit; parser errors return controlled responses; no attachment execution.
- **Archive bombs:** ZIP metadata only; at most 100 entries listed; no archive extraction; oversized member warning.
- **Malicious attachment:** SHA-256, extension/MIME/magic checks; optional in-memory YARA; optional ClamAV command-line scan; no detonation.
- **SSRF / redirect abuse:** URL analysis is lexical and passive. No automatic URL open, DNS resolution, redirect following or preview fetching.
- **Privacy leakage:** no external indicator sharing by default. VirusTotal domain and URLhaus checks require explicit consent and transmit only the selected indicator.
- **API abuse:** local upload size cap, CORS allow-list, role-key option, parameterized SQLite queries and audit events. Configure role keys before network deployment.
- **Privilege misuse:** viewer/analyst/admin role hierarchy. Analyst is required for analysis and incident changes; admin for model training and audit log access.
- **Prompt injection:** Any future LLM must receive untrusted email content as quoted data and must never call tools or issue response actions.
- **False positives / false negatives:** risk score and confidence are distinct; manual review flag; evidence details; analyst approval for response actions.

## Production hardening still required
Deploy behind TLS and a reverse proxy; set unique high-entropy API keys; restrict network access; use persistent encrypted storage and backups; configure retention and access policy; rotate credentials; monitor logs; isolate ClamAV/YARA scanning; pin and audit dependencies; add SSO and enterprise identity integration if deployed beyond a local academic demonstration. The local demo mode is intentionally convenient and is not a production security boundary.
