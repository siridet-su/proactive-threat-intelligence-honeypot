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

ชุดถัดไปจะเพิ่ม grouped split invariants, feature-order identity, model contracts และ
shadow/canonical non-interference
