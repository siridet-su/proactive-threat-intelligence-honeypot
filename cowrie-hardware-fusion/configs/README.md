# Configuration

พื้นที่สำหรับ versioned experiment, feature, model, calibration และ shadow-runtime
configuration ทุก config ที่มีผลต่อ dataset/model identity ต้องมี schema version และ
ถูกบันทึก hash ใน experiment หรือ release receipt

ไฟล์ปัจจุบัน:

- [Scenario catalog v1](scenario_catalog.v1.json)
- [Experimental Pi collector example](experimental_collector.pi_sensor.pilot.example.json)
  — ต้องยืนยัน disk/interface names จาก Pi ก่อนใช้งานจริง
- [Bounded benign-compute example](bounded_workload.benign_compute.example.json)
  — placeholder image/implementation/policy hashes; ห้าม execute จนแทนด้วย reviewed assets
- [Frozen hardware-impact experiment protocol v2](hardware_impact_experiment_protocol.v2.json)
  — authority สำหรับ label, scenarios, collection waves, feature profiles, fixed XGBoost
  parameters, leakage/safety controls และ promotion gates; validate content hash ก่อนเก็บข้อมูล
- [Scenario catalog v1](scenario_catalog.v1.json) มี Pi-specific paired controls สำหรับ
  `T1496.001` และ `T1499.002`; runtime spec/manifests จะ generate หลัง freeze ARM64 image ID
