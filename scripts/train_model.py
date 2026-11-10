from pathlib import Path
import argparse, json, sys
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'backend'))
from core.ml_pipeline import train_csv
p=argparse.ArgumentParser(description='Train/evaluate local PhishGuard ML baselines')
p.add_argument('csv',help='Labelled CSV dataset'); p.add_argument('--include-synthetic',action='store_true',help='Include synthetic smoke-test rows (not for benchmark claims)')
a=p.parse_args(); result=train_csv(a.csv,include_synthetic=a.include_synthetic)
print(json.dumps(result,indent=2)); print('\nSaved model and evaluation to backend/ml/artifacts/')
