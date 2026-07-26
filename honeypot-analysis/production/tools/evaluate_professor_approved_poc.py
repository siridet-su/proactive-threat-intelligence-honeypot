#!/usr/bin/env python3
"""One-time, fail-closed Final evaluation for the approved offline PoC."""
from __future__ import annotations

import argparse, hashlib, json, os, tempfile, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from production.prediction.next_behavior_baseline import predict_many, require_valid_baseline
from production.prediction.next_behavior_calibration import apply_temperature_mapping
from production.prediction.next_behavior_metrics import evaluate_next_behavior_predictions, paired_model_comparison
from production.prediction.next_behavior_model import load_checkpoint, predict_next_behavior
from production.prediction.next_behavior_professor_approved import (
    ProfessorApprovedPocError, require_valid_professor_approved_pretest_manifest,
    verify_professor_approved_pretest_artifacts,
)
from production.prediction.next_behavior_tensor import require_valid_vocabulary, tensorize_example
from production.utils.serialization import stable_json

EVALUATOR_SCHEMA = "next_behavior_professor_approved_final_evaluator.v1"
LEDGER_SCHEMA = "next_behavior_professor_approved_final_access_ledger.v1"

class ProfessorApprovedEvaluationError(ValueError): pass

def _sha(path: Path) -> str:
 d=hashlib.sha256()
 with path.open('rb') as h:
  for b in iter(lambda:h.read(1024*1024),b''): d.update(b)
 return d.hexdigest()
def _json(path: Path)->Any: return json.loads(path.read_text(encoding='utf-8'))
def _now()->str: return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def _ledger_path(manifest:Mapping[str,Any])->Path:
 p=Path(manifest['final_test']['path']); return p.parent/'.professor_approved_poc_final_access'/f"{manifest['manifest_sha256']}.json"
def _claim(manifest:Mapping[str,Any], output:Path)->Path:
 p=_ledger_path(manifest); p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 record={'schema_version':LEDGER_SCHEMA,'state':'opened','opened_at':_now(),'manifest_sha256':manifest['manifest_sha256'],'test_payload_sha256':manifest['final_test']['sha256'],'selected_seed':manifest['decision']['selection']['selected_seed'],'code_commit':manifest['code_commit'],'output_directory':str(output.resolve())}
 try: fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 except FileExistsError as exc: raise ProfessorApprovedEvaluationError('Final Test was already opened for this manifest') from exc
 try:
  os.write(fd,(stable_json(record)+'\n').encode()); os.fsync(fd)
 finally: os.close(fd)
 return p
def _finalize(path:Path, state:str, output:Path|None=None)->None:
 v=_json(path)
 if v.get('state')!='opened': raise ProfessorApprovedEvaluationError('ledger changed during evaluation')
 v.update({'state':state,'finalized_at':_now()})
 if output: v['completed_output_directory']=str(output.resolve())
 tmp=path.with_suffix('.tmp'); tmp.write_text(stable_json(v)+'\n'); os.replace(tmp,path)
def _transformer(example, model, spec, vocabulary, calibration, policy, checkpoint):
 raw=predict_next_behavior(model,tensorize_example(example,vocabulary),spec=spec)
 ranking=sorted(raw['tactic_logits'],key=lambda k:(-raw['tactic_logits'][k],k))
 input={'score_semantics':'raw_model_scores_not_probabilities','ranked_tactics':[{'tactic':k,'raw_score':raw['tactic_logits'][k],'rank':i+1,'calibrated_probability':None} for i,k in enumerate(ranking)],'terminal_outcome':{'label':raw['terminal_label'],'raw_score':raw['terminal_logit'],'calibrated_probability':None},'calibration':{'status':'not_implemented','method':'','mapping_sha256':'','fit_partition_membership_sha256':''}}
 cal=apply_temperature_mapping(input,calibration,fit_partition_membership_sha256=calibration['fit_partition_membership_sha256'],checkpoint_sha256=checkpoint,vocabulary_sha256=spec['vocabulary_sha256'],preprocessing_sha256=spec['preprocessing_sha256'])
 terminal=cal['terminal_outcome']['calibrated_probability']>=policy['terminal_threshold']
 selected=[] if terminal else sorted(x['tactic'] for x in cal['ranked_tactics'] if x['calibrated_probability']>=policy['tactic_threshold'])
 if not terminal and not selected: selected=[ranking[0]]
 return {'example_id':example['example_id'],'session_id':example['session_id'],'status':'predicted','predicted_terminal':terminal,'predicted_tactics':selected,'ranked_tactics':ranking,'calibrated_probabilities':{'tactics':{x['tactic']:x['calibrated_probability'] for x in cal['ranked_tactics']},'terminal':cal['terminal_outcome']['calibrated_probability']}}
def evaluate(manifest_path:Path, output:Path, *, bootstrap_samples:int=1000)->dict[str,Any]:
 manifest=require_valid_professor_approved_pretest_manifest(_json(manifest_path))
 if output.exists(): raise ProfessorApprovedEvaluationError('output already exists')
 try: verify_professor_approved_pretest_artifacts(manifest)
 except ProfessorApprovedPocError as exc: raise ProfessorApprovedEvaluationError('pre-test verification failed') from exc
 # Only this point opens Final bytes. The claim is durable before their hash/read.
 ledger=_claim(manifest,output)
 try:
  final=Path(manifest['final_test']['path'])
  if _sha(final)!=manifest['final_test']['sha256']: raise ProfessorApprovedEvaluationError('Final payload hash mismatch after opening')
  examples=[json.loads(line) for line in final.open(encoding='utf-8') if line.strip()]
  if len(examples)==0: raise ProfessorApprovedEvaluationError('Final payload empty')
  ids=hashlib.sha256(stable_json(sorted(x['example_id'] for x in examples)).encode()).hexdigest()
  if ids!=manifest['final_test']['membership_sha256']: raise ProfessorApprovedEvaluationError('Final membership mismatch')
  a=manifest['artifacts']; spec=_json(Path(a['model_spec']['path'])); vocabulary=require_valid_vocabulary(_json(Path(a['vocabulary']['path'])))
  model,meta=load_checkpoint(Path(a['selected_checkpoint']['path']),expected_spec=spec,expected_checkpoint_sha256=a['selected_checkpoint']['sha256'])
  cal=manifest['calibration']; policy=manifest['decision_policy']; t0=time.perf_counter()
  transformer=[_transformer(x,model,spec,vocabulary,cal,policy,a['selected_checkpoint']['sha256']) for x in examples]
  transformer_seconds=time.perf_counter()-t0
  vomm=require_valid_baseline(_json(Path(a['hard_backoff_vomm']['path']))); t0=time.perf_counter(); baseline=predict_many(vomm,examples); vomm_seconds=time.perf_counter()-t0
  metrics={'transformer':evaluate_next_behavior_predictions(examples,transformer,bootstrap_samples=bootstrap_samples),'hard_backoff_vomm':evaluate_next_behavior_predictions(examples,baseline,bootstrap_samples=bootstrap_samples)}
  paired=paired_model_comparison(examples,transformer,baseline,model_a='transformer',model_b='hard_backoff_vomm',bootstrap_samples=bootstrap_samples)
  result={'schema_version':EVALUATOR_SCHEMA,'status':'complete','manifest_sha256':manifest['manifest_sha256'],'final_counts':{'examples':len(examples),'sessions':len({x['session_id'] for x in examples})},'metrics':metrics,'paired':paired,'runtime':{'transformer_seconds':transformer_seconds,'transformer_examples_per_second':len(examples)/transformer_seconds,'vomm_seconds':vomm_seconds,'vomm_examples_per_second':len(examples)/vomm_seconds},'checkpoint_metadata':meta}
  tmp=Path(tempfile.mkdtemp(prefix='.'+output.name+'.',dir=output.parent)); (tmp/'final_evaluation.json').write_text(stable_json(result)+'\n'); (tmp/'SHA256SUMS.json').write_text(stable_json({'files':{'final_evaluation.json':_sha(tmp/'final_evaluation.json')}})+'\n'); os.replace(tmp,output); _finalize(ledger,'completed',output); return result
 except BaseException:
  _finalize(ledger,'failed'); raise
def main(argv:Sequence[str]|None=None)->int:
 p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--bootstrap-samples',type=int,default=1000);a=p.parse_args(argv);evaluate(a.manifest,a.output,bootstrap_samples=a.bootstrap_samples);return 0
if __name__=='__main__': raise SystemExit(main())
