import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from core.forensics import parse_email, analyze_evidence, analyze_urls

SAMPLE=b'''From: "IT Support" <help@paypa1-secure.example>\nReply-To: attacker@evil.example\nReturn-Path: <bounce@evil.example>\nTo: user@example.com\nSubject: URGENT verify your account\nAuthentication-Results: mx.example; spf=fail; dkim=none; dmarc=fail\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="x"\n\n--x\nContent-Type: text/plain; charset=utf-8\n\nYour account will expire. Login immediately at http://192.0.2.10/login?verify=account\n--x\nContent-Type: application/octet-stream; name="invoice.exe"\nContent-Disposition: attachment; filename="invoice.exe"\n\nnot-a-real-executable\n--x--\n'''

def test_parser_extracts_headers_urls_attachments():
    p=parse_email(SAMPLE)
    assert p['subject']=='URGENT verify your account'
    assert p['authentication']['spf']=='fail'
    assert len(p['urls'])==1
    assert p['attachments'][0]['dangerous_extension'] is True
    assert len(p['raw_sha256'])==64

def test_rules_return_transparent_indicators():
    p=parse_email(SAMPLE); r=analyze_evidence(p)
    assert r['risk_score']>0
    codes={x['code'] for x in r['signals']}
    assert 'spf_fail' in codes and 'dangerous_attachment_extension' in codes
    assert r['score_type']=='heuristic_risk_index_not_probability'

def test_url_lexical_flags():
    result=analyze_urls('visit https://bit.ly/login and http://192.0.2.10/password')
    assert 'shortened_url' in result[0]['flags']
    assert 'ip_literal' in result[1]['flags']

def test_empty_email_is_handled():
    p=parse_email(b'From: test@example.com\nSubject: hi\n\nHello')
    assert p['body']=='Hello'
    assert analyze_evidence(p)['verdict'] in {'legitimate','suspicious','phishing'}
