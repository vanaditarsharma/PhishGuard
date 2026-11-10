import sys
import pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))

from core.dataset import deduplicate, group_time_split, assign_near_duplicate_groups, quality_report


def _row(i, group, day, subject=None, body=None):
    return {
        'subject': subject or f'Project update {i}',
        'body': body or f'Please review document reference {i}.',
        'label': 'phishing' if i % 2 == 0 else 'legitimate',
        'group_id': group,
        'date': day,
        'source': 'unit-test',
        'license': 'test-data',
        'synthetic': 'true',
        'message_hash': f'hash-{i}',
        'group_id_provided': True,
    }


def test_group_time_split_has_no_group_leakage_and_is_chronological():
    rows = [_row(i, f'campaign-{i}', f'2026-{(i // 20) + 1:02d}-01') for i in range(60)]
    train, validation, test = group_time_split(rows)
    groups = [set(r['group_id'] for r in p) for p in (train, validation, test)]
    assert not (groups[0] & groups[1] or groups[0] & groups[2] or groups[1] & groups[2])
    assert max(r['date'] for r in train) <= min(r['date'] for r in validation)
    assert max(r['date'] for r in validation) <= min(r['date'] for r in test)


def test_exact_deduplication_and_quality_report():
    a = _row(1, 'g1', '2026-01-01')
    rows = [a, dict(a), _row(2, 'g2', '2026-02-01')]
    assert len(deduplicate(rows)) == 2
    report = quality_report(rows)
    assert report['duplicate_rows'] == 1
    assert report['missing_source'] == 0


def test_near_duplicate_grouping_merges_similar_messages():
    rows = [
        _row(1, 'g1', '2026-01-01', 'Urgent account verification', 'Please verify your account immediately using this secure portal.'),
        _row(2, 'g2', '2026-01-02', 'Urgent account verification', 'Please verify your account immediately using this secure portal!'),
        _row(3, 'g3', '2026-01-03', 'Quarterly meeting', 'The quarterly meeting agenda is attached for review.'),
    ]
    grouped = assign_near_duplicate_groups(rows, max_hamming=8)
    assert grouped[0]['group_id'] == grouped[1]['group_id']


def test_trainer_rejects_missing_dataset_provenance(tmp_path):
    import csv
    import pytest
    from core.ml_pipeline import train_csv
    path = tmp_path / 'bad.csv'
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['subject', 'body', 'label', 'group_id'])
        writer.writeheader()
        writer.writerow({'subject': 'A', 'body': 'B', 'label': 'phishing', 'group_id': 'campaign-a'})
    with pytest.raises(ValueError, match='provenance fields'):
        train_csv(path, output_dir=tmp_path / 'out')


def test_external_reputation_requires_explicit_consent():
    from core.threat_intel import lookup_virustotal_domain, lookup_urlhaus
    assert lookup_virustotal_domain('example.com', consent=False)['status'] == 'not_queried'
    assert lookup_urlhaus('https://example.com', consent=False)['status'] == 'not_queried'


def test_evidence_ablation_removes_only_selected_dimension():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
    from evidence_ablation import risk_for
    dimensions = {'authentication': 80, 'headers': 40, 'urls': 100, 'attachments': 0, 'language': 20, 'behaviour': 10}
    full = risk_for(dimensions)
    without_urls = risk_for(dimensions, 'urls')
    assert full > without_urls
    assert risk_for(dimensions, 'attachments') == full


def test_api_role_key_enforcement(monkeypatch):
    from fastapi import HTTPException
    from core.security import get_role
    monkeypatch.setenv('PHISHGUARD_API_KEYS', '{"viewer-token":"viewer","admin-token":"admin"}')
    assert get_role('viewer-token') == 'viewer'
    assert get_role('admin-token') == 'admin'
    with pytest.raises(HTTPException) as exc:
        get_role('wrong-token')
    assert exc.value.status_code == 401
