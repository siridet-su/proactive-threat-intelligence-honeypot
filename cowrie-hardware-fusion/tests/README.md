# Test Scope

รันจาก project folder:

```bash
pytest
```

ชุดแรกตรวจ feature semantics (`cpu_p95` รวมอยู่ด้วย), fixed-length TCN channels,
missing-data mask, duplicate/correlation rejection, prohibited feature boundary,
deterministic output และ derived JSON Schema

collector tests ตรวจ bounded spool rotation, fsync/publish contract, interrupted partial,
no-overwrite, idle-only safety gate, raw/receipt schema และ replay 90 samples เข้า dataset
builder

batch/split tests ตรวจ raw tampering, exact receipt membership, pilot exclusion,
deterministic connected-group assignment และ fail เมื่อ independent groups ไม่พอ

workload contract tests ตรวจ disposable-VM boundary, fixed input, no-network policy และ
CPU quota/intensity binding โดยไม่มี test ใด execute workload จริง

ชุดถัดไปจะเพิ่ม feature-order identity, model contracts และ shadow/canonical
non-interference
