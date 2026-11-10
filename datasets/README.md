# Dataset workflow

Do not confuse demo emails, synthetic smoke data, and a scientific benchmark.

## CSV schema

`subject,body,label,group_id,date,source,synthetic,license`

- `label`: `phishing` or `legitimate`; uncertain messages should be manually reviewed or excluded.
- `group_id`: campaign, sender cluster, source thread, or near-duplicate family. This is required to prevent group leakage.
- `date`: ISO date/time used for chronological holdout.
- `source` and `license`: provenance and redistribution terms.
- `synthetic`: `true` for generated examples. Excluded from training by default.

## Build from labelled .eml files

Create a manifest CSV with `path,label,group_id,date,source,license`, then run:

```bash
python scripts/build_dataset_from_eml.py datasets/manifest.csv --output datasets/curated.csv
python scripts/dataset_quality.py datasets/curated.csv
python scripts/train_model.py datasets/curated.csv
```

The builder redacts email addresses, phone-like strings and URLs from model text. Keep the raw `.eml` files in a controlled local research folder; do not commit private email data.

## Smoke-test dataset

`python scripts/generate_synthetic_smoke.py` creates 1,200 synthetic rows to verify ingestion/training code. To include these rows, explicitly pass `--include-synthetic`. These examples are templated and must never be used as evidence of real-world model accuracy.

## Public corpus acquisition

Potential sources to review include Enron (legitimate mail), SpamAssassin public corpus, and URLhaus / PhishTank / OpenPhish for URL indicators. Check each dataset's current terms, privacy implications, label definitions, and redistribution rules before use. Do not bundle third-party raw corpora in this project.
