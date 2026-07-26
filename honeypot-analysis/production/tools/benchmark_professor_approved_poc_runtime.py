#!/usr/bin/env python3
"""Benchmark frozen PoC models on Calibration inputs with labels ignored."""
from __future__ import annotations
import argparse, hashlib, json, math, os, platform, statistics, tempfile, time
from pathlib import Path
from typing import Any, Sequence
from production.prediction.next_behavior_baseline import (
    _artifact_tables, _predict_validated, _validated_example,
    require_valid_baseline,
)
from production.prediction.next_behavior_model import load_checkpoint, predict_next_behavior
from production.prediction.next_behavior_tensor import require_valid_vocabulary, tensorize_example
from production.utils.serialization import stable_json

def _sha(path: Path) -> str:
    digest=hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda:handle.read(1048576),b''):digest.update(block)
    return digest.hexdigest()
def _rss() -> int | None:
    try:
        for line in Path('/proc/self/status').read_text().splitlines():
            if line.startswith('VmRSS:'): return int(line.split()[1])*1024
    except Exception: return None
    return None
def _percentile(values:list[float], q:float)->float:
    values=sorted(values);pos=(len(values)-1)*q;lo=math.floor(pos);hi=math.ceil(pos);return values[lo] if lo==hi else values[lo]+(values[hi]-values[lo])*(pos-lo)
def _measure(call, cases, warmup:int, iterations:int)->dict[str,Any]:
    for index in range(warmup):call(cases[index%len(cases)])
    values=[];started_all=time.perf_counter_ns();peak=_rss()
    for index in range(iterations):
        started=time.perf_counter_ns();call(cases[index%len(cases)]);values.append((time.perf_counter_ns()-started)/1e6);current=_rss();peak=max(peak or 0,current or 0)
    seconds=(time.perf_counter_ns()-started_all)/1e9
    return {'iterations':iterations,'latency_ms':{'mean':statistics.fmean(values),'p50':_percentile(values,.5),'p95':_percentile(values,.95),'p99':_percentile(values,.99),'minimum':min(values),'maximum':max(values)},'throughput_per_second':iterations/seconds,'peak_process_rss_bytes':peak}
def benchmark(*,checkpoint:Path,checkpoint_sha256:str,model_spec:Path,vocabulary:Path,vomm:Path,calibration_examples:Path,output:Path,warmup:int=50,iterations:int=1000,sample_count:int=32)->dict[str,Any]:
    if output.exists():raise FileExistsError(output)
    examples=[]
    with calibration_examples.open(encoding='utf-8') as handle:
        for line in handle:
            # Targets are retained in the file but never read by this benchmark.
            value=json.loads(line)
            # Replace, rather than inspect, the real Calibration target.  The
            # baseline validator requires a structurally valid target even
            # though inference itself uses only model_input.
            value['target']={'outcome_type':'session_end','tactics':[],'terminal_outcome':'session_end_no_further_trusted_behavior'}
            examples.append(value)
            if len(examples)>=sample_count:break
    if not examples:raise ValueError('Calibration runtime sample is empty')
    spec=json.loads(model_spec.read_text());vocab=require_valid_vocabulary(json.loads(vocabulary.read_text()))
    before=_rss();started=time.perf_counter_ns();model,metadata=load_checkpoint(checkpoint,expected_spec=spec,expected_checkpoint_sha256=checkpoint_sha256);model_load_ms=(time.perf_counter_ns()-started)/1e6;after_model=_rss()
    tensors=[tensorize_example(example,vocab) for example in examples]
    transformer=_measure(lambda tensor:predict_next_behavior(model,tensor,spec=spec),tensors,warmup,iterations)
    started=time.perf_counter_ns();baseline=require_valid_baseline(json.loads(vomm.read_text()));vomm_load_ms=(time.perf_counter_ns()-started)/1e6;after_vomm=_rss()
    global_counts, contexts = _artifact_tables(baseline)
    validated_examples = [_validated_example(example) for example in examples]
    baseline_result=_measure(
        lambda example:_predict_validated(
            baseline, example, global_counts=global_counts, contexts=contexts
        ), validated_examples, warmup, iterations
    )
    result={'schema_version':'next_behavior_professor_approved_runtime.v1','status':'complete','input_scope':'sealed_calibration_inputs_labels_removed_before_inference','sample_count':len(examples),'warmup':warmup,'transformer':{'checkpoint_sha256':checkpoint_sha256,'artifact_size_bytes':checkpoint.stat().st_size,'load_ms':model_load_ms,'rss_before_bytes':before,'rss_after_load_bytes':after_model,'load_rss_delta_bytes':None if before is None or after_model is None else after_model-before,'parameter_count':metadata['parameter_count'],**transformer},'hard_backoff_vomm':{'artifact_sha256':_sha(vomm),'artifact_size_bytes':vomm.stat().st_size,'load_ms':vomm_load_ms,'rss_after_load_bytes':after_vomm,**baseline_result},'environment':{'cpu':platform.processor() or platform.machine(),'machine':platform.machine(),'python':platform.python_version(),'platform':platform.platform()}}
    output.parent.mkdir(parents=True,exist_ok=True);fd,name=tempfile.mkstemp(prefix='.'+output.name+'.',dir=output.parent)
    try:
        with os.fdopen(fd,'w') as handle:handle.write(stable_json(result)+'\n');handle.flush();os.fsync(handle.fileno())
        os.link(name,output)
    finally:
        try:Path(name).unlink()
        except FileNotFoundError:pass
    return result
def main(argv:Sequence[str]|None=None)->int:
    p=argparse.ArgumentParser();p.add_argument('--checkpoint',type=Path,required=True);p.add_argument('--checkpoint-sha256',required=True);p.add_argument('--model-spec',type=Path,required=True);p.add_argument('--vocabulary',type=Path,required=True);p.add_argument('--vomm',type=Path,required=True);p.add_argument('--calibration-examples',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--warmup',type=int,default=50);p.add_argument('--iterations',type=int,default=1000);p.add_argument('--sample-count',type=int,default=32);args=p.parse_args(argv);benchmark(**vars(args));return 0
if __name__=='__main__':raise SystemExit(main())
