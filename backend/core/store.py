"""Small SQLite persistence layer using parameterized SQL and JSON payloads."""
import json, os, sqlite3
from datetime import datetime, timezone
from pathlib import Path
DB_PATH = Path(os.getenv("PHISHGUARD_DB", Path(__file__).resolve().parents[1] / "phishguard.db"))

def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c=sqlite3.connect(DB_PATH, timeout=15); c.row_factory=sqlite3.Row; c.execute("PRAGMA journal_mode=WAL"); return c

def init_db():
    with connect() as c:
        c.executescript('''CREATE TABLE IF NOT EXISTS analyses(id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL, subject TEXT NOT NULL, verdict TEXT NOT NULL, severity TEXT NOT NULL, risk_score INTEGER NOT NULL, confidence REAL NOT NULL, technique TEXT NOT NULL, manual_review_required INTEGER NOT NULL, analyzed_at TEXT NOT NULL, payload_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open', assignee TEXT, notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL, FOREIGN KEY(analysis_id) REFERENCES analyses(id));
        CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS iocs(id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id INTEGER NOT NULL, ioc_type TEXT NOT NULL, value TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(analysis_id,ioc_type,value));
        CREATE TABLE IF NOT EXISTS awareness_feedback(id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id INTEGER NOT NULL, employee_id TEXT, outcome TEXT NOT NULL, training_score INTEGER, notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);''')

def save_analysis(payload):
    now=datetime.now(timezone.utc).isoformat(); payload["analyzed_at"]=now
    with connect() as c:
        cur=c.execute("INSERT INTO analyses(sender,subject,verdict,severity,risk_score,confidence,technique,manual_review_required,analyzed_at,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?)",(payload.get("sender","Unknown"),payload.get("subject","(No Subject)"),payload["verdict"],payload["severity"],payload["risk_score"],payload["confidence"],payload["technique"],int(payload["manual_review_required"]),now,json.dumps(payload)))
        payload["id"]=cur.lastrowid
        c.execute("UPDATE analyses SET payload_json=? WHERE id=?",(json.dumps(payload),cur.lastrowid))
        from core.advanced_intel import build_iocs
        for ioc in build_iocs(payload):
            c.execute("INSERT OR IGNORE INTO iocs(analysis_id,ioc_type,value,created_at) VALUES(?,?,?,?)",(cur.lastrowid,ioc['type'],ioc['value'],now))
        c.execute("INSERT INTO audit_log(actor,action,target,created_at) VALUES(?,?,?,?)",('system','analysis_created',str(cur.lastrowid),now))
    return payload

def list_analyses(limit=200):
    with connect() as c: rows=c.execute("SELECT payload_json FROM analyses ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    return [json.loads(r[0]) for r in rows]

def get_analysis(id):
    with connect() as c: row=c.execute("SELECT payload_json FROM analyses WHERE id=?",(id,)).fetchone()
    return json.loads(row[0]) if row else None

def dashboard():
    rows=list_analyses(5000); counts={k:0 for k in ("phishing","suspicious","legitimate")}; tech={}; trend={}
    for r in rows:
        counts[r["verdict"]]=counts.get(r["verdict"],0)+1; t=r.get("technique","none_detected")
        if t!="none_detected": tech[t]=tech.get(t,0)+1
        day=(r.get("analyzed_at") or "unknown")[:10]; trend.setdefault(day,{"phishing":0,"suspicious":0,"legitimate":0})[r["verdict"]]+=1
    return {"total_analyzed":len(rows),"verdict_counts":counts,"top_techniques":[{"technique":k,"count":v} for k,v in sorted(tech.items(),key=lambda x:x[1],reverse=True)[:8]],"trend_over_time":[{"date":k,**v} for k,v in sorted(trend.items())],"average_risk":round(sum(r["risk_score"] for r in rows)/len(rows),1) if rows else 0,"manual_review_count":sum(bool(r["manual_review_required"]) for r in rows)}

def create_incident(analysis_id):
    now=datetime.now(timezone.utc).isoformat()
    with connect() as c:
        cur=c.execute("INSERT INTO incidents(analysis_id,created_at,updated_at) VALUES(?,?,?)",(analysis_id,now,now)); return cur.lastrowid

def list_incidents():
    with connect() as c: rows=c.execute("SELECT i.*, a.subject, a.sender, a.verdict, a.severity, a.risk_score FROM incidents i JOIN analyses a ON a.id=i.analysis_id ORDER BY i.id DESC").fetchall()
    return [dict(r) for r in rows]

def update_incident(iid,status,assignee,notes):
    now=datetime.now(timezone.utc).isoformat()
    with connect() as c:
        cur=c.execute("UPDATE incidents SET status=?,assignee=?,notes=?,updated_at=? WHERE id=?",(status,assignee,notes,now,iid))
        return cur.rowcount>0


def list_iocs(limit=500):
    with connect() as c:
        rows=c.execute("SELECT i.ioc_type AS type,i.value,i.analysis_id,i.created_at,a.verdict,a.risk_score FROM iocs i JOIN analyses a ON a.id=i.analysis_id ORDER BY i.id DESC LIMIT ?",(limit,)).fetchall()
    return [dict(r) for r in rows]

def add_awareness_feedback(analysis_id,employee_id,outcome,training_score,notes):
    now=datetime.now(timezone.utc).isoformat()
    with connect() as c:
        cur=c.execute("INSERT INTO awareness_feedback(analysis_id,employee_id,outcome,training_score,notes,created_at) VALUES(?,?,?,?,?,?)",(analysis_id,employee_id,outcome,training_score,notes,now))
        c.execute("INSERT INTO audit_log(actor,action,target,created_at) VALUES(?,?,?,?)",(employee_id or 'employee','awareness_feedback',str(analysis_id),now))
        return cur.lastrowid

def awareness_stats():
    with connect() as c: rows=c.execute("SELECT outcome,COUNT(*) AS n,AVG(training_score) AS avg_score FROM awareness_feedback GROUP BY outcome").fetchall()
    return {'outcomes':[dict(r) for r in rows],'total':sum(r['n'] for r in rows)}

def audit(actor,action,target):
    now=datetime.now(timezone.utc).isoformat()
    with connect() as c: c.execute("INSERT INTO audit_log(actor,action,target,created_at) VALUES(?,?,?,?)",(actor,action,str(target),now))

def list_audit(limit=200):
    with connect() as c: rows=c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",(max(1,min(limit,1000)),)).fetchall()
    return [dict(r) for r in rows]
