"""Build a labelled CSV from a user-maintained manifest; raw messages stay local and are not copied to the output."""
import argparse,csv,re,sys
from email.utils import parsedate_to_datetime
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'backend'))
from core.forensics import parse_email
EMAIL=re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',re.I)
PHONE=re.compile(r'(?<!\w)(?:\+?\d[\d .()/-]{7,}\d)(?!\w)')
URL=re.compile(r'https?://\S+',re.I)
def redact(s):
    s=EMAIL.sub('[EMAIL]',s or '');s=PHONE.sub('[PHONE]',s);s=URL.sub('[URL]',s);return s
p=argparse.ArgumentParser();p.add_argument('manifest',help='CSV columns: path,label,group_id,date,source,license');p.add_argument('--output',default='datasets/curated.csv');a=p.parse_args()
base=Path(a.manifest).resolve().parent; rows=[]
with open(a.manifest,encoding='utf-8-sig',newline='') as f:
    for row in csv.DictReader(f):
        path=(base/row['path']).resolve()
        if not path.is_file(): raise SystemExit(f'Missing file: {path}')
        parsed=parse_email(path.read_bytes())
        try: email_date=parsedate_to_datetime(parsed.get('date','')).date().isoformat()
        except Exception: email_date=row.get('date','')
        rows.append({'subject':redact(parsed['subject']),'body':redact(parsed['body']),'label':row['label'],'group_id':row.get('group_id') or parsed['raw_sha256'],'date':row.get('date') or email_date,'source':row.get('source',''),'synthetic':'false','license':row.get('license','')})
out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True)
with out.open('w',newline='',encoding='utf-8') as f:
    w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
print(f'Wrote {len(rows)} redacted records to {out}. Review labels, provenance, licence and campaign groups before training.')
