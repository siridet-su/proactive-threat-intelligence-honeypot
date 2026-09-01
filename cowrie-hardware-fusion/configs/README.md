# Configuration

พื้นที่สำหรับ versioned experiment, feature, model, calibration และ shadow-runtime
configuration ทุก config ที่มีผลต่อ dataset/model identity ต้องมี schema version และ
ถูกบันทึก hash ใน experiment หรือ release receipt

ไฟล์ปัจจุบัน:

- [Scenario catalog v1](scenario_catalog.v1.json)
- [Experimental Pi collector example](experimental_collector.pi_sensor.pilot.example.json)
  — ต้องยืนยัน disk/interface names จาก Pi ก่อนใช้งานจริง
