"""Leakage-aware local text baselines for PhishGuard research.

Model selection uses validation data only. The final test partition is evaluated
once after the selected model is refit on train + validation. This avoids the
common mistake of selecting a model on the test set and reporting an optimistic
score. Group IDs are preserved across chronological partitions.
"""
from __future__ import annotations
from pathlib import Path
import json, time, joblib, random
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.metrics import (classification_report, confusion_matrix, roc_auc_score,
    average_precision_score, brier_score_loss, precision_score, recall_score, f1_score)
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from core.dataset import load_csv, deduplicate, quality_report, group_time_split

MODEL_DIR=Path(__file__).resolve().parents[1]/'ml'/'artifacts'


def _pipeline(name, min_df=2):
    if name=='logistic_regression':
        features=FeatureUnion([
            ('word',TfidfVectorizer(ngram_range=(1,2),max_features=60000,sublinear_tf=True,min_df=min_df)),
            ('char',TfidfVectorizer(analyzer='char',ngram_range=(3,5),max_features=60000,sublinear_tf=True,min_df=min_df))
        ])
        return Pipeline([('tfidf',features),('clf',LogisticRegression(max_iter=2000,class_weight='balanced',random_state=42))])
    if name=='linear_svm':
        return Pipeline([('tfidf',TfidfVectorizer(ngram_range=(1,2),max_features=50000,sublinear_tf=True,min_df=min_df)),('clf',CalibratedClassifierCV(LinearSVC(class_weight='balanced',random_state=42),cv=3))])
    return Pipeline([('tfidf',TfidfVectorizer(ngram_range=(1,2),max_features=30000,min_df=min_df)),('clf',CalibratedClassifierCV(estimator=RandomForestClassifier(n_estimators=250,class_weight='balanced_subsample',random_state=42,n_jobs=-1,max_features='sqrt'),cv=3,method='sigmoid'))])


def _cluster_bootstrap_ci(y_true,y_pred,groups,iterations=1000,seed=42):
    """Campaign/group-level percentile bootstrap, preserving within-group dependence."""
    from collections import defaultdict
    buckets=defaultdict(list)
    for i,g in enumerate(groups): buckets[str(g)].append(i)
    keys=list(buckets)
    if len(keys)<2:
        return {'lower_95':None,'upper_95':None,'method':'not_available: fewer than two independent test groups'}
    rng=random.Random(seed); values=[]
    for _ in range(iterations):
        selected=[rng.choice(keys) for _ in keys]
        idx=[i for key in selected for i in buckets[key]]
        values.append(f1_score([y_true[i] for i in idx],[y_pred[i] for i in idx],average='macro',zero_division=0))
    values.sort()
    return {'lower_95':round(values[int(.025*len(values))],4),'upper_95':round(values[min(len(values)-1,int(.975*len(values)))],4),'method':'campaign/group-level percentile bootstrap; resamples whole groups'}


def _evaluate(model, rows, text_fn):
    X=[text_fn(r) for r in rows]; y=[r['label'] for r in rows]
    start=time.perf_counter(); pred=model.predict(X); elapsed=(time.perf_counter()-start)/max(1,len(X))
    classes=list(model.classes_); proba=model.predict_proba(X)[:,classes.index('phishing')] if hasattr(model,'predict_proba') and 'phishing' in classes else None
    f1=f1_score(y,pred,average='macro',zero_division=0)
    entry={'classification_report':classification_report(y,pred,output_dict=True,zero_division=0),'confusion_matrix_labels':['legitimate','phishing'],'confusion_matrix':confusion_matrix(y,pred,labels=['legitimate','phishing']).tolist(),'macro_f1':round(f1,4),'macro_f1_cluster_bootstrap_95ci':_cluster_bootstrap_ci(y,pred,[r['group_id'] for r in rows]),'independent_test_groups':len({r['group_id'] for r in rows}),'precision_phishing':round(precision_score(y,pred,pos_label='phishing',zero_division=0),4),'recall_phishing':round(recall_score(y,pred,pos_label='phishing',zero_division=0),4),'false_positive_rate':round(sum(1 for t,p in zip(y,pred) if t=='legitimate' and p=='phishing')/max(1,sum(t=='legitimate' for t in y)),4),'inference_ms_per_email':round(elapsed*1000,4),'test_samples':len(y)}
    if proba is not None:
        binary=[int(v=='phishing') for v in y]
        entry.update({'roc_auc':round(roc_auc_score(binary,proba),4),'pr_auc':round(average_precision_score(binary,proba),4),'brier_score':round(brier_score_loss(binary,proba),4)})
    else: entry.update({'roc_auc':None,'pr_auc':None,'brier_score':None})
    return entry


def train_csv(csv_path, output_dir=MODEL_DIR, include_synthetic=False):
    rows=deduplicate(load_csv(csv_path))
    missing=[k for k in ('date','source','license') if any(not str(r.get(k,'')).strip() for r in rows)]
    if missing: raise ValueError('Research dataset is missing required provenance fields: '+', '.join(missing))
    if any(not r.get('group_id_provided') for r in rows): raise ValueError('Every row must provide an explicit campaign/thread group_id. Do not rely on automatic exact-hash grouping for the headline experiment.')
    if not include_synthetic: rows=[r for r in rows if str(r.get('synthetic','')).lower() not in {'1','true','yes'}]
    if len(rows)<60: raise ValueError('At least 60 non-duplicate labelled messages are required for train/validation/test evaluation.')
    counts={k:sum(r['label']==k for r in rows) for k in ('phishing','legitimate')}
    if min(counts.values())<20: raise ValueError('At least 20 examples per class are required.')
    train,val,test=group_time_split(rows)
    if min(len({r['label'] for r in part}) for part in (train,val,test))<2:
        raise ValueError('Both labels must occur in train, validation and final test partitions. Add more campaign groups across time.')
    text=lambda r:(r.get('subject','')+' '+r.get('body','')).strip()
    Xtr=[text(r) for r in train]; ytr=[r['label'] for r in train]
    Xval=[text(r) for r in val]; yval=[r['label'] for r in val]
    # Avoid min_df failures on smaller valid corpora.
    min_df=2 if len(train)>=100 else 1
    output_dir=Path(output_dir); output_dir.mkdir(parents=True,exist_ok=True)
    validation={}; best_name=None; best_f1=-1
    for name in ('logistic_regression','linear_svm','random_forest'):
        model=_pipeline(name,min_df=min_df); start=time.perf_counter(); model.fit(Xtr,ytr); fit_seconds=time.perf_counter()-start
        pred=model.predict(Xval); score=f1_score(yval,pred,average='macro',zero_division=0)
        validation[name]={'macro_f1':round(score,4),'classification_report':classification_report(yval,pred,output_dict=True,zero_division=0),'fit_seconds':round(fit_seconds,4),'validation_samples':len(val)}
        if score>best_f1: best_f1=score; best_name=name
    # Final test is never used for model selection.
    final_rows=train+val; final_model=_pipeline(best_name,min_df=min_df)
    start=time.perf_counter(); final_model.fit([text(r) for r in final_rows],[r['label'] for r in final_rows]); final_fit=time.perf_counter()-start
    test_result=_evaluate(final_model,test,text)
    joblib.dump(final_model,output_dir/'phishguard_text_model.joblib')
    metadata={'best_model_selected_on_validation':best_name,'validation_results':validation,'final_test_result':test_result,'dataset':quality_report(rows),'partition_sizes':{'train':len(train),'validation':len(val),'test':len(test)},'split':'chronological group-preserving; a group never crosses partitions','selection_metric':'validation macro F1','final_fit_seconds':round(final_fit,4),'random_seed':42,'synthetic_included':include_synthetic,'confidence_interval_note':'Campaign/group-level percentile bootstrap on the final test partition.','warning':'Metrics describe this dataset and split only. External validity depends on provenance, label quality, language, drift and representative campaigns. This script does not download or fabricate a benchmark dataset.'}
    (output_dir/'evaluation.json').write_text(json.dumps(metadata,indent=2),encoding='utf-8')
    return metadata


def predict_text(subject, body, model_dir=MODEL_DIR):
    artifact=Path(model_dir)/'phishguard_text_model.joblib'
    if not artifact.exists(): return {'status':'not_trained','phishing_probability':None,'model':'none'}
    model=joblib.load(artifact); text=(subject or '')+' '+(body or '')
    classes=list(model.classes_)
    if 'phishing' not in classes: return {'status':'invalid_model','phishing_probability':None,'model':'unknown'}
    p=float(model.predict_proba([text])[0][classes.index('phishing')])
    return {'status':'complete','phishing_probability':round(p,5),'predicted_label':'phishing' if p>=0.5 else 'legitimate','model':'trained_local_text_model','probability_note':'Probability calibration is conditional on representative training data and validation; it is not a universal guarantee.'}
