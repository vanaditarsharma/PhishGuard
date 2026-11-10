"""Text feature ablation: subject-only vs body-only vs combined; group/time split."""
import argparse,json,sys,time
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report,confusion_matrix,roc_auc_score,average_precision_score
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'backend'))
from core.dataset import load_csv,deduplicate,group_time_split
p=argparse.ArgumentParser();p.add_argument('csv');p.add_argument('--output',default='backend/ml/artifacts/ablation.json');a=p.parse_args()
rows=deduplicate(load_csv(a.csv));train,val,test=group_time_split(rows)
results={}
for mode in ('subject','body','combined'):
    get=lambda r:r.get('subject','') if mode=='subject' else r.get('body','') if mode=='body' else r.get('subject','')+' '+r.get('body','')
    model=Pipeline([('tfidf',TfidfVectorizer(ngram_range=(1,2),sublinear_tf=True,min_df=2,max_features=50000)),('clf',LogisticRegression(max_iter=1500,class_weight='balanced',random_state=42))])
    start=time.perf_counter();fit_rows=train+val;model.fit([get(r) for r in fit_rows],[r['label'] for r in fit_rows]);pred=model.predict([get(r) for r in test]);prob=model.predict_proba([get(r) for r in test])[:,list(model.classes_).index('phishing')]
    results[mode]={'fit_seconds':round(time.perf_counter()-start,4),'report':classification_report([r['label'] for r in test],pred,output_dict=True,zero_division=0),'confusion_matrix':confusion_matrix([r['label'] for r in test],pred,labels=['legitimate','phishing']).tolist(),'roc_auc':roc_auc_score([int(r['label']=='phishing') for r in test],prob),'pr_auc':average_precision_score([int(r['label']=='phishing') for r in test],prob)}
out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps({'split':'chronological group-preserving','sizes':{'train':len(train),'validation':len(val),'final_fit_train_plus_validation':len(train)+len(val),'test':len(test)},'test_groups':len({r['group_id'] for r in test}),'results':results},indent=2));print(out)
