# Schemas

งานแรกของโฟลเดอร์นี้คือกำหนดสัญญาต่อไปนี้ก่อนเก็บ full dataset:

- experiment/run manifest
- raw telemetry sample
- Cowrie command-to-run correlation
- impact labels และ ground-truth TTP set
- derived training window
- shadow prediction record

ทุก schema ต้องแยก metric scope เช่น `pi_sensor`, `backend_guest`, `backend_cgroup`
และ `target_process` เพื่อไม่รวมค่าจากคนละเครื่องหรือคนละ authority boundary

ไฟล์ปัจจุบัน:

- [Experiment run manifest schema](experiment_run_manifest.v1.schema.json)
- [Hardware telemetry sample schema](hardware_telemetry_sample.v1.schema.json)
- [Derived training window schema](derived_training_window.v1.schema.json)
- [Experimental collector config schema](experimental_collector_config.v1.schema.json)
- [Experiment collection receipt schema](experiment_collection_receipt.v1.schema.json)
- [Example run manifest](examples/experiment_run_manifest.v1.example.json)
- [Example telemetry sample](examples/hardware_telemetry_sample.v1.example.json)
