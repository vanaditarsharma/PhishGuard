# PhishGuard 2.0

### Explainable phishing detection, email forensics and incident triage

PhishGuard is a local-first defensive email analysis platform. It helps an analyst inspect suspicious `.eml` messages, review the evidence behind a risk assessment, and manage follow-up investigations.

The project combines a browser dashboard with a Python API. It is intended for academic demonstration, defensive security learning and controlled research—not as a production email gateway.

## Features

- **Email forensics:** RFC/MIME parsing of message headers, plain-text and HTML bodies, received-chain details and attachments.
- **Sender identity checks:** comparison of `From`, `Reply-To` and `Return-Path`, plus selected display-name and header anomalies.
- **Authentication observations:** extraction of SPF, DKIM and DMARC results when present in receiver-stamped headers.
- **URL analysis:** passive inspection of URL structure and lexical indicators, including IP-literal hosts, shorteners, punycode and suspicious URL patterns. PhishGuard does not automatically visit links.
- **Attachment inspection:** hashes, file signatures, extension/MIME mismatches and safe archive metadata inspection. Attachments are not executed.
- **Explainable risk assessment:** evidence across authentication, headers, URLs, attachments, language and behaviour, with reasons and analyst-facing guidance.
- **Investigation dashboard:** searchable analysis history, evidence details, IOC register and PDF forensic reports.
- **Incident workflow:** open, investigate, contain and resolve cases, with assignees and notes.
- **Awareness feedback:** record reporting and training outcomes.
- **Optional reputation checks:** VirusTotal domain and URLhaus URL lookups, only after an analyst explicitly consents to share the indicator.
- **Research utilities:** dataset preparation, redaction, duplicate grouping, baseline training and evaluation scripts, kept separate from the normal dashboard workflow.

## Technology

| Layer | Technology |
|---|---|
| Frontend | HTML5, CSS3, Vanilla JavaScript, Chart.js |
| Backend | Python, FastAPI, Uvicorn |
| Storage | SQLite |
| Analysis | MIME parsing, explainable evidence rules, URL and attachment inspection |
| Research | scikit-learn, dataset preparation and evaluation scripts |
| Testing | pytest, HTTPX, GitHub Actions |

## Screenshots

Screenshots can be added here as the interface is finalized. Suggested files: `docs/images/dashboard.png`, `docs/images/email-analysis.png` and `docs/images/incident-view.png`.

## Run locally on Windows

### Requirements

- Windows 10/11
- Python 3.11 recommended (the included GitHub Actions workflow tests on Python 3.11)
- VS Code is recommended but not required

### 1. Get the project

Clone the repository:

```powershell
git clone https://github.com/vanaditarsharma/PhishGuard.git
cd PhishGuard
```

Or download the repository ZIP from GitHub and extract it.

### 2. Create and activate a virtual environment

In VS Code, open the project folder (`File` → `Open Folder`), then open an integrated terminal (`Terminal` → `New Terminal`).

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks script activation, run this in the same terminal and activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

From the project root:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Start the backend

Open a **second VS Code terminal**. Activate the same environment there, then run:

```powershell
cd backend
uvicorn app:app --reload
```

The API should be available at `http://127.0.0.1:8000`. Keep this terminal running.

### 5. Start the frontend

In the first terminal, return to the project root if needed:

```powershell
cd ..
python scripts/serve_frontend.py
```

If that terminal is already at the project root, run only the `python` command.

Open the dashboard at:

- Frontend: <http://127.0.0.1:8080>
- API health: <http://127.0.0.1:8000/api/health>
- Interactive API docs: <http://127.0.0.1:8000/docs>

The SQLite database is created automatically when the backend starts. The local database file is ignored by Git.

## Run tests

From the project root, with the virtual environment active:

```powershell
python -m pytest -q
```

A GitHub Actions workflow in `.github/workflows/tests.yml` runs the test suite on pushes and pull requests.

## Optional integrations

Optional integrations are not required for the core local analysis:

- **YARA:** install `backend/requirements-optional.txt` and configure local rules.
- **ClamAV:** install ClamAV separately and make `clamscan` available on `PATH`.
- **QR extraction:** requires the optional Python packages and the system ZBar library.
- **VirusTotal:** configure `VIRUSTOTAL_API_KEY` in the backend environment. A domain is shared only after explicit analyst consent.
- **URLhaus:** a URL is shared only after explicit analyst consent. Review and sanitize URLs first; query strings can contain private tokens or identifiers.

Copy `.env.example` to `.env` only if you need environment configuration. Never commit `.env` or real API keys.

## Research and dataset workflow

The application dashboard does not provide an interactive model-training workbench. Research scripts and methodology documents are provided separately under `scripts/` and `docs/`.

The bundled `.eml` files and synthetic-data generator are demonstration/test fixtures—not a representative scientific benchmark. No real-world accuracy claim or large labelled benchmark is supplied by this repository.

Before conducting model evaluation:

1. Collect messages only from sources you are permitted to use.
2. Record source, licence/provenance, date and thread or near-duplicate group.
3. Redact personal information where appropriate.
4. Use group-aware and time-aware train/validation/test splits.
5. Report false positives, per-class metrics and limitations; do not report synthetic smoke-test results as real-world performance.

See:

- [`docs/RESEARCH_METHODOLOGY.md`](docs/RESEARCH_METHODOLOGY.md)
- [`docs/ACADEMIC_EVALUATION_PROTOCOL.md`](docs/ACADEMIC_EVALUATION_PROTOCOL.md)
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- [`docs/FEATURE_MATRIX.md`](docs/FEATURE_MATRIX.md)
- [`datasets/README.md`](datasets/README.md)

## Important security boundaries and limitations

- **Authentication results are observations, not independent verification.** PhishGuard extracts SPF/DKIM/DMARC results from message headers; it does not independently perform DNS SPF evaluation or cryptographically verify DKIM signatures. Untrusted headers can be forged.
- **No automatic URL fetching or redirect resolution.** URLs are inspected passively to reduce server-side request forgery (SSRF) risk.
- **Attachments are not executed.** Optional YARA/ClamAV checks are static inspection, not sandbox detonation.
- **Risk score is heuristic.** It is an explainable weighted index, not a calibrated probability. Thresholds and weights need validation against representative labelled data.
- **Reputation no-hit does not mean safe.** External services may have incomplete or delayed coverage.
- **Campaign similarity is an investigation lead**, not proof of maliciousness or attribution.
- **Local demo mode is not production security.** When API keys are not configured, the API is intended for a single-user local demonstration. Do not expose it to the public internet. Production deployment needs hardened authentication, authorization, storage, secrets management, monitoring, retention controls and a reviewed network-egress design.
- **No enterprise SSO, mailbox quarantine or automatic message deletion** is provided.
- SHA-256 hashes help check file integrity but do not by themselves establish legal chain of custody.

## Project structure

```text
PhishGuard/
├── backend/
│   ├── app.py
│   ├── core/              # email forensics, evidence, storage, reports, threat intel
│   ├── data/              # safe sample email fixtures
│   └── yara/              # starter YARA rule
├── frontend/              # dashboard HTML, CSS and JavaScript
├── scripts/               # local server and research utilities
├── datasets/              # dataset workflow and templates
├── tests/                 # automated tests
├── docs/                  # architecture, threat model and research protocols
├── .github/workflows/     # CI test workflow
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Licence and attribution

This repository is an upgraded derivative of the original PhishGuard project. The original MIT licence and copyright notice are retained in [`LICENSE`](LICENSE).


