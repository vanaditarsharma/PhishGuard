"""PhishGuard 2.0 API for defensive email analysis and incident handling."""
from __future__ import annotations
import os, time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from core.forensics import parse_email, analyze_evidence, coaching_for
from core import store
from core.security import require_role
from core.reporting import make_pdf
from core.threat_intel import lookup_virustotal_domain, lookup_urlhaus

MAX_UPLOAD=int(os.getenv('MAX_UPLOAD_BYTES',10*1024*1024))
@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init_db(); yield
app=FastAPI(title='PhishGuard 2.0 API',version='2.1.0',description='Explainable local-first phishing detection, email forensics, campaign correlation and incident response.',lifespan=lifespan)
origins=[x.strip() for x in os.getenv('CORS_ORIGINS','http://127.0.0.1:8080,http://localhost:8080').split(',') if x.strip()]
app.add_middleware(CORSMiddleware,allow_origins=origins,allow_methods=['GET','POST','PATCH'],allow_headers=['Content-Type','X-API-Key'])
_rate_events=defaultdict(deque)
@app.middleware('http')
async def basic_rate_limit(request, call_next):
    # Lightweight per-process guard for local demos; use a gateway/WAF for multi-worker production.
    if request.url.path.startswith('/api/'):
        key=(request.client.host if request.client else 'unknown', request.url.path.split('/')[2] if len(request.url.path.split('/'))>2 else 'api')
        now=time.time(); q=_rate_events[key]
        while q and now-q[0]>60: q.popleft()
        limit=30 if request.url.path=='/api/analyze' else 120
        if len(q)>=limit:
            from fastapi.responses import JSONResponse
            return JSONResponse({'detail':'Rate limit exceeded. Try again shortly.'},status_code=429)
        q.append(now)
    return await call_next(request)

@app.get('/')
def root(): return {'name':'PhishGuard 2.0','version':'2.1.0','status':'online','mode':'offline-first','docs':'/docs'}
@app.get('/api/health')
def health():
    configured=bool(os.getenv('PHISHGUARD_API_KEYS'))
    return {'status':'ok','database':'sqlite','safe_url_mode':'passive','api_key_auth_configured':configured,'security_note':'Local demo mode is open when PHISHGUARD_API_KEYS is unset; configure role keys before network deployment.' if not configured else 'Role-based API key authentication is enabled.'}

@app.post('/api/analyze')
async def analyze(file: UploadFile=File(...), role=Depends(require_role('analyst'))):
    name=(file.filename or '').lower()
    if not name.endswith('.eml'): raise HTTPException(400,'Only .eml files are supported.')
    raw=await file.read(MAX_UPLOAD+1)
    if len(raw)>MAX_UPLOAD: raise HTTPException(413,f'Email exceeds {MAX_UPLOAD//(1024*1024)} MiB limit.')
    if not raw: raise HTTPException(400,'Uploaded email is empty.')
    try:
        parsed=parse_email(raw); evidence=analyze_evidence(parsed)
        payload={**parsed,**evidence,'coaching_message':coaching_for(evidence)}
        saved=store.save_analysis(payload); store.audit(role,'email_analyzed',saved['id']); return saved
    except Exception as e: raise HTTPException(422,f'Could not parse or analyze email: {type(e).__name__}: {e}')

@app.get('/api/analyses')
def analyses(limit:int=Query(100,ge=1,le=500),role=Depends(require_role('viewer'))): return store.list_analyses(limit)
@app.get('/api/analyses/{analysis_id}')
def analysis(analysis_id:int,role=Depends(require_role('viewer'))):
    row=store.get_analysis(analysis_id)
    if not row: raise HTTPException(404,'Analysis not found.')
    return row
@app.get('/api/analyses/{analysis_id}/report.pdf')
def report(analysis_id:int,role=Depends(require_role('viewer'))):
    row=store.get_analysis(analysis_id)
    if not row: raise HTTPException(404,'Analysis not found.')
    return StreamingResponse(make_pdf(row),media_type='application/pdf',headers={'Content-Disposition':f'attachment; filename=phishguard-analysis-{analysis_id}.pdf'})
@app.get('/api/dashboard')
def dashboard(role=Depends(require_role('viewer'))): return store.dashboard()

@app.get('/api/incidents')
def incidents(role=Depends(require_role('viewer'))): return store.list_incidents()
class IncidentUpdate(BaseModel):
    status:str=Field(pattern='^(open|investigating|contained|resolved|false_positive)$')
    assignee:str|None=Field(default=None,max_length=120)
    notes:str=Field(default='',max_length=5000)
@app.post('/api/incidents/{analysis_id}')
def open_incident(analysis_id:int,role=Depends(require_role('analyst'))):
    if not store.get_analysis(analysis_id): raise HTTPException(404,'Analysis not found.')
    iid=store.create_incident(analysis_id); store.audit(role,'incident_opened',iid); return {'incident_id':iid,'status':'open'}
@app.patch('/api/incidents/{incident_id}')
def patch_incident(incident_id:int,body:IncidentUpdate,role=Depends(require_role('analyst'))):
    if not store.update_incident(incident_id,body.status,body.assignee,body.notes): raise HTTPException(404,'Incident not found.')
    store.audit(role,'incident_updated',incident_id); return {'updated':True,'incident_id':incident_id}

@app.get('/api/iocs')
def iocs(limit:int=Query(500,ge=1,le=2000),role=Depends(require_role('viewer'))): return store.list_iocs(limit)
class IntelRequest(BaseModel):
    indicator:str=Field(min_length=1,max_length=2048)
    consent_to_share:bool=False
@app.post('/api/threat-intel/virustotal-domain')
def vt_domain(body:IntelRequest,role=Depends(require_role('analyst'))):
    domain=body.indicator.strip().lower()
    if '/' in domain or '://' in domain or ' ' in domain: raise HTTPException(400,'Provide a domain only, not a full URL or path.')
    return lookup_virustotal_domain(domain,body.consent_to_share)
@app.post('/api/threat-intel/urlhaus')
def urlhaus(body:IntelRequest,role=Depends(require_role('analyst'))):
    if not body.indicator.lower().startswith(('http://','https://')): raise HTTPException(400,'Provide a complete http(s) URL.')
    return lookup_urlhaus(body.indicator,body.consent_to_share)

class AwarenessFeedback(BaseModel):
    analysis_id:int
    employee_id:str|None=Field(default=None,max_length=120)
    outcome:str=Field(pattern='^(reported_correctly|missed|false_alarm|training_completed)$')
    training_score:int|None=Field(default=None,ge=0,le=100)
    notes:str=Field(default='',max_length=2000)
@app.post('/api/awareness/feedback')
def awareness_feedback(body:AwarenessFeedback,role=Depends(require_role('analyst'))):
    if not store.get_analysis(body.analysis_id): raise HTTPException(404,'Analysis not found.')
    fid=store.add_awareness_feedback(body.analysis_id,body.employee_id,body.outcome,body.training_score,body.notes); return {'feedback_id':fid,'saved':True}
@app.get('/api/awareness/summary')
def awareness_summary(role=Depends(require_role('viewer'))): return store.awareness_stats()

@app.get('/api/audit')
def audit(limit:int=Query(200,ge=1,le=1000),role=Depends(require_role('admin'))): return store.list_audit(limit)
