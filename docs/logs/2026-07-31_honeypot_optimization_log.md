# Honeypot Architecture & Optimization Log 🚀
**Date**: July 2026

## 1. การปรับแต่ง Hardware Agent (Optimization)
- **ปัญหา**: `hardware-agent` ส่งข้อมูลดิบจำนวนมาก (เช่น จำนวน Packets ยิบย่อย, CPU แต่ละคอร์, พื้นที่ว่างใน Disk) เข้า Database ทุกๆ 30 วินาที ซึ่งกินพื้นที่ MongoDB มากเกินความจำเป็น
- **การแก้ไข**: 
  - เข้าไปแก้โค้ด Go เพื่อ "หั่นฟิลด์ขยะ" ออก เหลือเฉพาะข้อมูลสำคัญ ได้แก่ `cpu_percent`, `temperature`, `mem_used_bytes`, `mem_percent`, `disk_used_bytes`, `disk_percent` และ ความเร็วเน็ต (Throughput `rx_mbps`, `tx_mbps`)
  - ปรับความถี่จาก 30 วินาที เป็น **10 วินาที** เพื่อให้กราฟ Throughput บนหน้าเว็บมีความเป็น Real-time มากขึ้น แต่ไม่ถี่ระดับ 5 วินาทีเพื่อเป็นการถนอมโควต้าการเขียนข้อมูลของ MongoDB Cloud

## 2. การแก้ปัญหา Processor Agent ค้างหลัง Reboot
- **ปัญหา**: หลังจากเซิร์ฟเวอร์โดน Restart ตัว Redis หายไป ทำให้ "คิวท่อดูดข้อมูล (Consumer Group)" สำหรับ `processor-agent` ถูกล้างหายไปด้วย เมื่อมันกลับมาทำงานจึงเกิด Error: `NOGROUP No such key...`
- **การแก้ไข**: รันคำสั่ง `redis-cli XGROUP CREATE` เพื่อสร้าง Consumer Group ให้ `raw:hardware`, `raw:cowrie` และ `raw:zeek:*` ทั้งหมดใหม่ ส่งผลให้ Agent กลับมาดูดข้อมูลเข้า MongoDB ได้สมบูรณ์

## 3. ความต่างของเซ็นเซอร์ Zeek และ Cowrie (Architecture)
- **Zeek (Network Layer)**: ทำหน้าที่เหมือน "รปภ. ประตูหน้า" จะคอยเฝ้าดูตลอดการเชื่อมต่อ (TCP Connection) และจะ **"เขียน Log ใบเสร็จสรุปยอดเพียง 1 บรรทัด"** ก็ต่อเมื่อคนร้าย "วางสาย/ปิดการเชื่อมต่อ" (เช่น เมื่อ Cowrie ตัดการเชื่อมต่อแฮกเกอร์หลังจากสาดข้อมูลครบ 120 วินาที (Timeout limit) Zeek จะบันทึกยอด 90MB ทันที) ข้อดีคือป้องกัน Database บวมจากการเก็บทุกๆ Packet
- **Cowrie (Application Layer)**: ทำงานแบบ **Real-time** แฮกเกอร์พิมพ์คำสั่งอะไร หรือลองรหัสผ่านอะไร Cowrie จะส่ง Log ลงคิวทันทีโดยไม่ต้องรอจบ Session

## 4. Concurrency ของ Go Agent และ Redis Streams
- **Goroutine (`go func()`)**: ใน `collector-agent` มีการสั่ง Spawn Thread แยกต่างหาก (1 Goroutine ต่อ 1 ไฟล์) เพื่ออ่าน Log ของ Cowrie และ Zeek (หลายไฟล์) แบบขนานกัน (Parallel) ทำให้การรับข้อมูลลื่นไหล ไม่เกิดคอขวด
- **Redis Streams แทน `chan`**: เราใช้คิวของ Redis (Streams) ทำหน้าที่เสมือน Channel ขนาดใหญ่ข้ามโปรแกรม (Decoupling) หากโปรแกรมใดตาย ข้อมูลยังคงปลอดภัยอยู่ใน Redis

## 5. การเตรียมพร้อมสำหรับ Local LLM 🧠
- การที่โครงสร้าง Honeypot ทั้งหมดกิน CPU เพียง **5.8%** เป็นข้อดีอย่างยิ่ง เพราะการรัน Local LLM (เช่น Ollama) เพื่อประเมิน Risk Score และพฤติกรรมแฮกเกอร์ (Bot vs Human vs APT) จากฐานข้อมูล Keystroke จะดึง CPU 100% (Inference load) การประหยัด Resource ของระบบพื้นฐานไว้ตั้งแต่เนิ่นๆ จึงเป็นแผนที่ถูกต้องสำหรับการก้าวสู่ AI-Driven Security
