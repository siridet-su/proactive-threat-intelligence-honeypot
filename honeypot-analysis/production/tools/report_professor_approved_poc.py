#!/usr/bin/env python3
"""Render privacy-safe, immutable reports from a completed Final result only."""
from __future__ import annotations
import argparse, csv, hashlib, json, os, tempfile
from pathlib import Path
from typing import Any, Sequence
from production.utils.serialization import stable_json

def _sha(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def _write(p:Path,s:str): p.parent.mkdir(parents=True,exist_ok=True);p.write_text(s,encoding='utf-8')
def render(result_path:Path, output:Path)->dict[str,Any]:
 if output.exists():raise FileExistsError(output)
 r=json.loads(result_path.read_text(encoding='utf-8'))
 if r.get('status')!='complete':raise ValueError('result is not complete')
 t=r['metrics']['transformer'];v=r['metrics']['hard_backoff_vomm']
 tmp=Path(tempfile.mkdtemp(prefix='.'+output.name+'.',dir=output.parent))
 try:
  rows=[]
  for label in sorted(t['multilabel_tactics']['per_class']):
   a=t['multilabel_tactics']['per_class'][label];b=v['multilabel_tactics']['per_class'][label]
   rows.append({'label':label,'transformer_precision':a['precision'],'transformer_recall':a['recall'],'transformer_f1':a['f1'],'transformer_support':a['support'],'vomm_precision':b['precision'],'vomm_recall':b['recall'],'vomm_f1':b['f1'],'vomm_support':b['support']})
  with (tmp/'per_label.csv').open('w',newline='',encoding='utf-8') as f:
   w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
  def agg(m):
   x=m['multilabel_tactics']['all_classes'];return {'macro_f1':x['macro']['f1'],'micro_f1':x['micro']['f1'],'weighted_f1':x['weighted']['f1'],'balanced_accuracy':x['macro']['balanced_accuracy'],'coverage':m['coverage']['coverage'],'abstention_rate':m['coverage']['abstention_rate']}
  summary={'schema_version':'next_behavior_professor_approved_report.v1','final_counts':r['final_counts'],'transformer':agg(t),'hard_backoff_vomm':agg(v),'runtime':r['runtime'],'not_determinable':['calibration_diagnostics','latency_percentiles','isolated_model_memory','full_evaluator_peak_memory','provenance_confidence_agreement_buckets','sequence_length_buckets'],'limitations':['within-Zenodo temporal holdout','classifier-derived weak labels','advisory forecast only','original BLOCKED_AT_SELECTION defense-evasion gate remains preserved']}
  _write(tmp/'summary.json',stable_json(summary)+'\n')
  md=['# Professor-approved corrected-target PoC: immutable Final result','',f"Final cohort: {r['final_counts']['sessions']:,} sessions; {r['final_counts']['examples']:,} examples.",'','| Model | Macro-F1 | Micro-F1 | Weighted-F1 | Balanced accuracy | Coverage |','|---|---:|---:|---:|---:|---:|']
  for name,m in [('Transformer',summary['transformer']),('Hard-backoff VOMM',summary['hard_backoff_vomm'])]:md.append(f"| {name} | {m['macro_f1']:.6f} | {m['micro_f1']:.6f} | {m['weighted_f1']:.6f} | {m['balanced_accuracy']:.6f} | {m['coverage']:.6f} |")
  md+=['','The original experiment remains **BLOCKED_AT_SELECTION**. This separately authorised result accepts the known Selection defense-evasion limitation; predictions are advisory only and observed command-derived evidence remains authoritative.','', '## Thai interpretation','ผลลัพธ์นี้เป็นการประเมิน PoC แบบครั้งเดียวภายใต้ข้อมูล Zenodo ตามเวลาและป้ายกำกับแบบ weak label ไม่ใช่การยืนยันภายนอกหรือหลักฐานเจตนาของผู้โจมตี.']
  _write(tmp/'THESIS_SUMMARY.md','\n'.join(md)+'\n')
  # Deliberately simple SVG has no data beyond public metric aggregates.
  svg='<svg xmlns="http://www.w3.org/2000/svg" width="640" height="220"><text x="20" y="28">Final macro-F1 (immutable PoC evaluation)</text>'
  for i,(name,m,color) in enumerate([('Transformer',summary['transformer'],'#286090'),('VOMM',summary['hard_backoff_vomm'],'#777')]):
   y=70+i*70;w=int(500*m['macro_f1']);svg+=f'<text x="20" y="{y}">{name}</text><rect x="120" y="{y-20}" width="{w}" height="30" fill="{color}"/><text x="{130+w}" y="{y}">{m["macro_f1"]:.4f}</text>'
  _write(tmp/'macro_f1.svg',svg+'</svg>')
  _write(tmp/'LIMITATIONS.md','\n'.join('* '+x for x in summary['limitations']+['Unavailable measurements are explicitly NOT_DETERMINABLE; they were not recomputed after Final opening.'])+'\n')
  sums={str(p.relative_to(tmp)):_sha(p) for p in sorted(tmp.rglob('*')) if p.is_file()};_write(tmp/'SHA256SUMS.json',stable_json({'files':sums,'source_final_evaluation_sha256':_sha(result_path)})+'\n');os.replace(tmp,output)
 finally:
  if tmp.exists(): import shutil;shutil.rmtree(tmp,ignore_errors=True)
 return summary
def main(argv:Sequence[str]|None=None)->int:
 p=argparse.ArgumentParser();p.add_argument('--result',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args(argv);render(a.result,a.output);return 0
if __name__=='__main__':raise SystemExit(main())
