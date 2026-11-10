import argparse,csv,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'backend'))
from core.dataset import load_csv,assign_near_duplicate_groups
p=argparse.ArgumentParser();p.add_argument('input');p.add_argument('--output',default='datasets/grouped.csv');p.add_argument('--max-hamming',type=int,default=5);a=p.parse_args()
rows=assign_near_duplicate_groups(load_csv(a.input),a.max_hamming);out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True)
with out.open('w',newline='',encoding='utf-8') as f:
 w=csv.DictWriter(f,fieldnames=list(rows[0].keys()));w.writeheader();w.writerows(rows)
print(f'Wrote {len(rows)} records with near-duplicate groups to {out}. Review groups before training.')
