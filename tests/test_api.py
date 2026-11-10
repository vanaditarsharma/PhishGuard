import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from fastapi.testclient import TestClient
import app
from core import store
store.init_db()

client=TestClient(app.app)

def test_health():
    health=client.get('/api/health').json()
    assert health['status']=='ok'
    assert health['safe_url_mode']=='passive'
    assert 'llm_required' not in health

def test_reject_non_eml():
    r=client.post('/api/analyze',files={'file':('bad.txt',b'hello','text/plain')})
    assert r.status_code==400

def test_analyze_eml():
    content=b'From: Test <test@example.com>\nTo: user@example.com\nSubject: Meeting notes\n\nPlease see notes for tomorrow.'
    r=client.post('/api/analyze',files={'file':('meeting.eml',content,'message/rfc822')})
    assert r.status_code==200, r.text
    j=r.json(); assert 'risk_index' in j['score_type'] and 'not_probability' in j['score_type']; assert 'dimensions' in j
