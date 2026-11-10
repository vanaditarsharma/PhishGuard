"""Opt-in reputation lookups. No indicator is transmitted unless the operator explicitly enables a provider."""
from __future__ import annotations
import os, requests

TIMEOUT=5

def lookup_virustotal_domain(domain: str, consent: bool=False) -> dict:
    if not consent: return {'provider':'VirusTotal','status':'not_queried','reason':'Explicit sharing consent is required.'}
    key=os.getenv('VIRUSTOTAL_API_KEY','')
    if not key: return {'provider':'VirusTotal','status':'not_configured'}
    # Domain-only lookup avoids transmitting the full email or private URL path/query.
    try:
        r=requests.get(f'https://www.virustotal.com/api/v3/domains/{domain}',headers={'x-apikey':key},timeout=TIMEOUT); r.raise_for_status(); data=r.json().get('data',{}).get('attributes',{}); stats=data.get('last_analysis_stats',{})
        return {'provider':'VirusTotal','status':'complete','domain':domain,'last_analysis_stats':stats,'reputation':data.get('reputation'),'retrieved_from':'VirusTotal API','note':'A zero detection count is not proof of safety.'}
    except requests.RequestException as e: return {'provider':'VirusTotal','status':'error','message':str(e)}

def lookup_urlhaus(url: str, consent: bool=False) -> dict:
    if not consent: return {'provider':'URLhaus','status':'not_queried','reason':'Explicit sharing consent is required.'}
    try:
        r=requests.post('https://urlhaus-api.abuse.ch/v1/url/',data={'url':url},timeout=TIMEOUT); r.raise_for_status(); d=r.json()
        return {'provider':'URLhaus','status':'complete','query_status':d.get('query_status'),'threat':d.get('threat'),'url_status':d.get('url_status'),'note':'No result does not establish that a URL is benign.'}
    except requests.RequestException as e: return {'provider':'URLhaus','status':'error','message':str(e)}
