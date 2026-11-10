"""Dataset validation, deduplication and leakage-resistant group/time split utilities."""
from __future__ import annotations
import csv, hashlib, json, re
from pathlib import Path
from collections import Counter
from datetime import datetime

def normalize_text(s): return re.sub(r'\s+',' ',(s or '').lower()).strip()
def message_hash(row): return hashlib.sha256((normalize_text(row.get('subject',''))+'\n'+normalize_text(row.get('body',''))).encode()).hexdigest()
def load_csv(path):
    rows=[]
    with open(path,encoding='utf-8-sig',newline='') as f:
        for n,row in enumerate(csv.DictReader(f),start=2):
            label=(row.get('label') or '').strip().lower()
            if label not in {'phishing','legitimate'}: raise ValueError(f'Row {n}: label must be phishing or legitimate')
            if not (row.get('subject') or row.get('body')): raise ValueError(f'Row {n}: subject or body is required')
            row['label']=label; row['group_id_provided']=bool((row.get('group_id') or '').strip()); row['group_id']=(row.get('group_id') or message_hash(row)); row['message_hash']=message_hash(row)
            date_value=(row.get('date') or '').strip()
            if date_value:
                try: datetime.fromisoformat(date_value.replace('Z','+00:00'))
                except ValueError: raise ValueError(f'Row {n}: date must be ISO-8601 (YYYY-MM-DD or timestamp)')
            rows.append(row)
    return rows

def quality_report(rows):
    duplicates=Counter(r['message_hash'] for r in rows)
    return {'samples':len(rows),'class_counts':dict(Counter(r['label'] for r in rows)),'unique_messages':len(duplicates),'duplicate_rows':sum(v-1 for v in duplicates.values()),'group_count':len({r['group_id'] for r in rows}),'missing_source':sum(not r.get('source') for r in rows),'missing_date':sum(not r.get('date') for r in rows),'missing_license':sum(not r.get('license') for r in rows),'missing_explicit_group_id':sum(not r.get('group_id_provided',False) for r in rows),'label_policy':'Binary phishing / legitimate. Suspicious or uncertain items should be reviewed or excluded from supervised training.'}

def deduplicate(rows):
    seen=set(); out=[]
    for r in rows:
        h=r['message_hash']
        if h not in seen: seen.add(h); out.append(r)
    return out

def group_time_split(rows, test_fraction=.2, validation_fraction=.1):
    """Group-preserving chronological split. Groups never span train/validation/test."""
    groups={}
    for r in rows: groups.setdefault(r['group_id'],[]).append(r)
    def date_key(group):
        vals=[x.get('date','') for x in group if x.get('date')]
        return max(vals) if vals else '0000-00-00'
    ordered=sorted(groups.values(),key=date_key)
    n=len(ordered); ntest=max(1,round(n*test_fraction)); nval=max(1,round(n*validation_fraction)) if n>=5 else 0
    test_groups=ordered[-ntest:]; val_groups=ordered[-(ntest+nval):-ntest] if nval else []; train_groups=ordered[:n-ntest-nval]
    flatten=lambda gs:[r for g in gs for r in g]
    train,val,test=flatten(train_groups),flatten(val_groups),flatten(test_groups)
    if not train or not test: raise ValueError('Not enough independent groups for a group/time split. Add more distinct campaign groups.')
    return train,val,test

def write_manifest(rows,path):
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True)
    fields=['message_hash','label','source','date','group_id','synthetic','license']
    with p.open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
        for r in rows: w.writerow({k:r.get(k,'') for k in fields})

def _simhash(text):
    import hashlib
    tokens=re.findall(r"[a-z0-9]+",normalize_text(text))
    shingles=[' '.join(tokens[i:i+3]) for i in range(max(1,len(tokens)-2))] or tokens
    weights=[0]*64
    for token in shingles:
        h=int.from_bytes(hashlib.blake2b(token.encode(),digest_size=8).digest(),'big')
        for bit in range(64): weights[bit]+=1 if (h>>bit)&1 else -1
    return sum((1<<bit) for bit,w in enumerate(weights) if w>=0)

def assign_near_duplicate_groups(rows,max_hamming=5):
    """Return copied rows with merged group IDs for near duplicates using banded SimHash candidate generation."""
    rows=[dict(r) for r in rows]; hashes=[_simhash(r.get('subject','')+' '+r.get('body','')) for r in rows]
    parent=list(range(len(rows)))
    def find(x):
        while parent[x]!=x: parent[x]=parent[parent[x]];x=parent[x]
        return x
    def union(a,b):
        a,b=find(a),find(b)
        if a!=b: parent[b]=a
    buckets={}
    original_groups={}
    for i,r in enumerate(rows):
        g=r.get('group_id')
        if g: original_groups.setdefault(g,[]).append(i)
    for indexes in original_groups.values():
        for j in indexes[1:]: union(indexes[0],j)
    for i,h in enumerate(hashes):
        for band in range(8):
            key=(band,(h>>(band*8))&255)
            for j in buckets.get(key,[]):
                if (hashes[i]^hashes[j]).bit_count()<=max_hamming: union(i,j)
            buckets.setdefault(key,[]).append(i)
    merged={}
    for i,r in enumerate(rows):
        root=find(i); merged.setdefault(root,[]).append(r.get('group_id') or r['message_hash'])
    group_names={root:'near-'+hashlib.sha1('|'.join(sorted(set(vals))).encode()).hexdigest()[:12] for root,vals in merged.items()}
    for i,r in enumerate(rows): r['group_id']=group_names[find(i)]
    return rows
