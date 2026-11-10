"""Evaluate deterministic risk dimensions and leave-one-dimension-out ablations.

Input manifest CSV columns: path,label,group_id,date,source,license.
Only the chronological group-preserving test partition is scored.
"""
import argparse, csv, json, sys
from pathlib import Path
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
from core.forensics import parse_email, analyze_evidence
from core.dataset import group_time_split

WEIGHTS={'authentication':.15,'headers':.15,'urls':.25,'attachments':.20,'language':.10,'behaviour':.15}

def verdict(score):
    return 'phishing' if score>=60 else 'suspicious' if score>=20 else 'legitimate'

def risk_for(dimensions, removed=None):
    return round(sum(weight*(0 if key==removed else dimensions.get(key,0)) for key,weight in WEIGHTS.items()))

def main():
    p=argparse.ArgumentParser();p.add_argument('manifest');p.add_argument('--output',default='backend/ml/artifacts/evidence_ablation.json');a=p.parse_args()
    base=Path(a.manifest).resolve().parent; rows=[]
    with open(a.manifest,encoding='utf-8-sig',newline='') as f:
        for row in csv.DictReader(f):
            if row.get('label') not in {'phishing','legitimate'}: raise SystemExit('Manifest labels must be phishing or legitimate.')
            if not all(row.get(k,'').strip() for k in ('group_id','date','source','license')): raise SystemExit('Each row needs group_id, date, source and license.')
            path=(base/row['path']).resolve()
            if not path.is_file(): raise SystemExit(f'Missing email: {path}')
            parsed=parse_email(path.read_bytes()); evidence=analyze_evidence(parsed)
            rows.append({**row,'dimensions':evidence['dimensions']})
    train,val,test=group_time_split(rows)
    y=[r['label'] for r in test]; arms={'rules_only':None,**{f'without_{d}':d for d in WEIGHTS}}
    results={}
    for name,removed in arms.items():
        scores=[risk_for(r['dimensions'],removed) for r in test]; pred=[verdict(s) for s in scores]
        results[name]={'classification_report':classification_report(y,pred,labels=['legitimate','phishing'],output_dict=True,zero_division=0),'confusion_matrix_labels':['legitimate','phishing'],'confusion_matrix':confusion_matrix(y,pred,labels=['legitimate','phishing']).tolist(),'macro_f1':round(f1_score(y,pred,labels=['legitimate','phishing'],average='macro',zero_division=0),4),'precision_phishing':round(precision_score(y,pred,pos_label='phishing',zero_division=0),4),'recall_phishing':round(recall_score(y,pred,pos_label='phishing',zero_division=0),4),'false_positive_rate':round(sum(t=='legitimate' and p=='phishing' for t,p in zip(y,pred))/max(1,sum(t=='legitimate' for t in y)),4),'mean_risk_index':round(sum(scores)/max(1,len(scores)),2)}
    output={'experiment':'deterministic evidence leave-one-dimension-out ablation','split':'chronological group-preserving','partition_sizes':{'train':len(train),'validation':len(val),'test':len(test)},'test_groups':len({r['group_id'] for r in test}),'results':results,'warning':'Thresholds and weights are initial expert-authored settings. Results are dataset-specific; this ablation is not evidence of generalization without a representative labelled corpus.'}
    out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(output,indent=2),encoding='utf-8');print(out)
if __name__=='__main__': main()
