"""Offline URL feature engineering and indicator extraction."""
from __future__ import annotations
import hashlib, ipaddress, math, re
from collections import Counter
from difflib import SequenceMatcher
from urllib.parse import urlparse

BRANDS = ("paypal", "microsoft", "google", "apple", "amazon", "dhl", "netflix", "linkedin", "github", "dropbox", "adobe", "zoom", "outlook", "office365")
SUSPICIOUS_TOKENS = ("login", "verify", "secure", "account", "update", "wallet", "password", "billing", "invoice", "auth", "signin", "confirm", "unlock", "webscr")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "tiny.cc", "lnkd.in"}

def shannon_entropy(value: str) -> float:
    if not value: return 0.0
    counts=Counter(value)
    return round(-sum((n/len(value))*math.log2(n/len(value)) for n in counts.values()),4)

def _registrable_approx(host: str) -> str:
    parts=host.lower().strip('.').split('.')
    return '.'.join(parts[-2:]) if len(parts)>=2 else host

def url_features(url: str) -> dict:
    normalized=url if '://' in url else 'http://'+url
    p=urlparse(normalized); host=(p.hostname or '').lower().strip('.')
    labels=host.split('.') if host else []
    try: ipaddress.ip_address(host); is_ip=True
    except ValueError: is_ip=False
    path_query=p.path+'?'+p.query
    decoded= re.sub(r'%[0-9a-fA-F]{2}', 'x', path_query)
    sim=[]
    clean=host.replace('-', '').replace('.', '')
    for brand in BRANDS:
        ratio=SequenceMatcher(None,clean,brand).ratio()
        if brand not in clean and ratio>=0.72: sim.append({'brand':brand,'similarity':round(ratio,3)})
    flags=[]
    if p.scheme!='https': flags.append('non_https')
    if host in SHORTENERS: flags.append('shortened_url')
    if is_ip: flags.append('ip_literal')
    if len(labels)>=4: flags.append('many_subdomains')
    if '@' in p.netloc: flags.append('userinfo')
    if host.startswith('xn--') or '.xn--' in host: flags.append('idn_punycode')
    if any(x in (host+path_query).lower() for x in SUSPICIOUS_TOKENS): flags.append('suspicious_token')
    if len(url)>100: flags.append('long_url')
    if shannon_entropy(path_query)>4.0 and len(path_query)>20: flags.append('high_entropy_path')
    if sim: flags.append('brand_lookalike')
    try: unicode_host=host.encode('ascii').decode('idna') if host.startswith('xn--') or '.xn--' in host else host
    except UnicodeError: unicode_host=host
    return {'url':url,'domain':host,'registrable_domain_approx':_registrable_approx(host),'scheme':p.scheme,'path_length':len(p.path),'query_length':len(p.query),'url_length':len(url),'subdomain_count':max(0,len(labels)-2),'host_entropy':shannon_entropy(host),'path_entropy':shannon_entropy(decoded),'digit_ratio':round(sum(c.isdigit() for c in host)/max(1,len(host)),3),'hyphen_count':host.count('-'),'is_ip_literal':is_ip,'unicode_display':unicode_host,'brand_similarity':sim,'flags':sorted(set(flags))}

def build_iocs(analysis: dict) -> list[dict]:
    out=[]
    for u in analysis.get('urls',[]):
        if u.get('domain'): out.append({'type':'domain','value':u['domain'],'source':'email_url'})
        if u.get('url'): out.append({'type':'url','value':u['url'],'source':'email_url'})
    for a in analysis.get('attachments',[]):
        if a.get('sha256'): out.append({'type':'sha256','value':a['sha256'],'source':'attachment'})
        for qr in a.get('scan',{}).get('qr_codes',[]):
            if qr.startswith(('http://','https://')): out.append({'type':'url','value':qr,'source':'attachment_qr_code'})
    if analysis.get('from_domain'): out.append({'type':'domain','value':analysis['from_domain'],'source':'sender'})
    unique={(x['type'],x['value']):x for x in out}
    return list(unique.values())

