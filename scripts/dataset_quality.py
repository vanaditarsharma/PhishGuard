from pathlib import Path
import argparse,json,sys
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'backend'))
from core.dataset import load_csv,deduplicate,quality_report
p=argparse.ArgumentParser();p.add_argument('csv');a=p.parse_args();rows=load_csv(a.csv);print(json.dumps({'before':quality_report(rows),'after_exact_dedup':quality_report(deduplicate(rows))},indent=2))
