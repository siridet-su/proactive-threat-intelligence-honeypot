# Test Scope

รันจาก project folder:

```bash
pytest
```

ชุดแรกตรวจ feature semantics (`cpu_p95` รวมอยู่ด้วย), service-pressure/cgroup aggregates,
fixed-length TCN channels, missing-data mask, feature/channel order hashes,
duplicate/correlation rejection, prohibited feature boundary, deterministic output และ
derived JSON Schema

collector tests ตรวจ bounded spool rotation, fsync/publish contract, interrupted partial,
no-overwrite, idle-only safety gate, raw/receipt schema และ replay 90 samples เข้า dataset
builder

batch/split tests ตรวจ raw tampering, exact receipt membership, pilot exclusion,
deterministic connected-group assignment และ fail เมื่อ independent groups ไม่พอ

workload contract tests ตรวจ disposable-VM boundary, fixed input, no-network policy และ
CPU quota/intensity binding โดยไม่มี test ใด execute workload จริง

instrumentation tests ตรวจ 7-scenario matrix/schema/hash bindings, pilot exclusion,
matched benign/malicious hardware treatment, observed-impact evidence gate และ candidate
host/target signal summary

model-profile tests ตรวจ contract/schema/content hash, builder/order binding, exact nested
XGBoost/TCN profiles, simulator-artifact/label rejection, TCN missingness policy และ CLI
validation หลัง serialize/reload

ชุดถัดไปจะเพิ่ม development-matrix generation และ shadow/canonical non-interference
