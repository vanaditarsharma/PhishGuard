# Backend

Run from this directory:

```bash
python -m pip install -r requirements.txt
uvicorn app:app --reload
```

OpenAPI docs are served at `http://127.0.0.1:8000/docs`.

- `core/forensics.py`: MIME parsing and transparent evidence rules.
- `core/advanced_intel.py`: URL feature engineering and IOC extraction.
- `core/attachment_scanner.py`: file signatures, safe ZIP metadata, optional YARA and ClamAV.
- `core/ml_pipeline.py`: local model comparison, group/time split, calibration metrics and artifact loading.
- `core/store.py`: SQLite persistence, incident, IOC, awareness and audit records.
- `core/threat_intel.py`: opt-in external reputation checks.

No attachment is executed. No URL is fetched automatically.
