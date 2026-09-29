# H1/H2 และ G1/G2 — ข้อความที่เจ้าของโครงการอนุมัติ

วันที่ 28 ก.ย. 2026 เจ้าของโครงการอนุมัติข้อความตามร่างในบทสนทนา การอนุมัติข้อความไม่เท่ากับการยืนยันว่า backend version นี้ผ่าน release gate หรือขึ้นหน้าเว็บแล้ว

## H1 — เตรียมไฟล์แต่ยังไม่พบการสั่งรัน

- เงื่อนไข: file write ตามด้วย permission change บน resolved path เดียวกัน ลำดับเวลาและผลสำเร็จที่ Cowrie รายงานต้องรองรับ และยังไม่มี execution attempt บน path นั้น
- ทางเลือก: อาจเตรียมไฟล์เพื่อใช้ภายหลัง หรือเป็นการจัดการไฟล์ตามปกติ/กิจกรรมหยุดไว้
- ตรวจต่อ: file audit, สิทธิ์ไฟล์ และ process telemetry บนระบบที่ได้รับอนุญาต
- ขอบเขต: ไม่ยืนยันการเปลี่ยนแปลงบน host จริงหรือเจตนา

## H2 — เรียกใช้หลังพยายาม transfer แต่ยังไม่ยืนยันการรับไฟล์

- เงื่อนไข: transfer attempt ตามด้วย execution attempt บน resolved path เดียวกัน มีลำดับเวลาและผลที่ Cowrie รายงานรองรับ แต่ไม่มี direct transfer event ใน session
- ทางเลือก: อาจพยายามใช้เนื้อหาที่ขอจาก remote หรือ fetch อาจล้มเหลวและคำสั่งอ้างไฟล์ที่มีอยู่ก่อน
- ตรวจต่อ: direct transfer event/hash ที่ผูก path, file audit และ process telemetry
- ขอบเขต: ไม่กล่าวว่ารับไฟล์หรือ execute สำเร็จ; เมื่อมี direct transfer event ที่ยังไม่ผูก path แน่ชัดให้ abstain

## G1 — ตรวจการเปลี่ยนแปลงไฟล์

- เลือกจาก file write หรือ permission change ที่ Cowrie รายงานสำเร็จและมี resolved/linkable path; รวมหลาย fact ของ path เดียวเป็น manual action เดียว
- ให้คนตรวจ file audit, สถานะและสิทธิ์ไฟล์ และ approved change record
- สิ่งที่ลดน้ำหนัก: ไม่พบการเปลี่ยนแปลง, operation ล้มเหลว, หรือมี approved change record

## G2 — ตรวจลำดับสั่งรันแล้วลบไฟล์

- เลือกจาก execution attempt ตามด้วย deletion command บน resolved path เดียวกัน โดยมี supported relationship และ timestamp-supported chronology
- ให้คนตรวจ process audit, file audit และ approved change record
- ไม่อนุมานเจตนาลบร่องรอยหรือผลบน host จริง

ทั้ง G1 และ G2 ต้องมี `requires_manual_approval=true`, `safe_to_auto_execute=false` และ `execution_integration=not_implemented` ไม่มีสิทธิ์สั่ง response อัตโนมัติ
