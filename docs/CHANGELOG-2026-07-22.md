# Honeypot pipeline change log — 2026-07-22

เอกสารนี้บันทึกการเปลี่ยนแปลงระบบ Collector, Processor, Zeek และ MongoDB ของวันนี้ เพื่อให้ตรวจสอบย้อนหลังและ rollback ได้

## Baseline ก่อนแก้ไข

- `honeypot-collector.service`, `honeypot-processor.service` และ `cowrie.service` ทำงานอยู่
- Redis `raw:cowrie` และ `raw:zeek:*` ไม่มี event; มีเพียง `raw:hardware` ที่มีข้อมูล
- Cowrie current JSON log มีขนาด 0 byte แต่มี rotated logs เดิมประมาณ 68,682 events
- ZeekControl แสดง logger, manager, proxy และ workers ทั้งหมดเป็น `crashed`
- Zeek ไม่มี systemd service และ `node.cfg` ยังมี ZeroTier worker เก่า
- Processor เขียน eventซ้ำทั้ง `normalized_events` และ `enriched_events`, ไม่ใช้ stable dedup key และ Mongo write error ไม่ทำให้ message retry

## 1. Zeek lifecycle และ interface

- เพิ่ม tracked config `zeek/node.cfg`
- ใช้เฉพาะ `wlan0` และ `tailscale0`; นำ ZeroTier worker ออกจาก production capture
- เพิ่ม `systemd-services/zeek.service` ให้ `zeekctl deploy` อัตโนมัติหลัง network/Tailscale พร้อม
- เหตุผล: ก่อนหน้านี้ Zeek ไม่กลับมาทำงานเองหลัง reboot และ status `crashed` ทั้ง cluster

## Rollback

ไฟล์ระบบเดิมจะถูกสำรองด้วย suffix `.pre-pipeline-20260722` ก่อนติดตั้ง config ใหม่ การ rollback ใช้ไฟล์สำรองแล้วรัน `zeekctl deploy` อีกครั้ง


## 2. Collector

- Cowrie ใช้ `dst_ip` และ `dst_port` จาก payload จริง และ fallback เป็น LAN IP/22 เฉพาะกรณีไม่มีค่า
- เพิ่ม Zeek sources: `dns`, `http`, `files`, `notice` นอกเหนือจาก `conn`, `ssh`, `ssl`
- เพิ่ม raw stream retention จาก 5,000 เป็น 50,000 (`RAW_STREAM_MAXLEN` override ได้)
- ลด log spam เมื่อ Zeek log ยังไม่เกิด จาก retry ทุก 3 วินาทีเป็น 30 วินาที
- historical Cowrie rotated logs ยังไม่ถูก import อัตโนมัติ เพื่อไม่ปน test data เดิมกับ production

## 3. Processor และ MongoDB schema

- เปลี่ยน durable collection หลักเป็น `events` collection เดียว; หยุดเขียนข้อมูลซ้ำลง `normalized_events`/`enriched_events`
- ใช้ collector `dedup_id` เป็น stable `event_id` และ Mongo `_id`
- เขียนด้วย upsert + ``; replay event เดิมไม่สร้าง document ซ้ำ
- Mongo write ต้องสำเร็จก่อน raw Redis message ถูก ACK; เมื่อ Atlas มีปัญหา message จะค้าง pending เพื่อ retry
- Redis output เหลือ `event:canonical` streamเดียวและเก็บสูงสุดประมาณ 50,000 events
- `timestamp` เป็น BSON Date, ports เป็น number และตัด field/subdocument ว่างก่อนเขียน
- เพิ่ม `session.id` เพื่อเชื่อม Cowrie session หรือ Zeek UID
- เพิ่ม indexes สำหรับ timestamp, source/event type, source IP และ session
- เพิ่ม mapping Zeek DNS/HTTP/files/notice, risk สำหรับ MySQL 3306 และรู้จัก private/Tailscale ranges

## ข้อควรระวังด้านข้อมูล

- collection เดิมยังไม่ถูกลบหรือ migrate เพื่อรักษาข้อมูล test จนกว่าจะยืนยัน schema ใหม่
- attempted honeypot password ยังคงอยู่ใน canonical event เพราะใช้วิเคราะห์ credential attack ได้ ควรจำกัดสิทธิ์ Atlas/API ไม่ให้ dashboard สาธารณะอ่าน field นี้
- current log tail เริ่มจากท้ายไฟล์ใน production; historical backfill ต้องเป็นคำสั่งแยกและยังไม่ถูกรัน


## 4. Deployment และ verification

- สำรอง `/usr/local/zeek/etc/node.cfg` และ `/etc/honeypot-agent.env` เป็น `.pre-pipeline-20260722`
- ติดตั้ง/enable `zeek.service`; logger, manager, proxy, `worker-wlan0`, `worker-tailscale0` เป็น `running`
- production env: `READ_FROM_START=false`, raw retention 50,000, allowed ports รวม 3306, overlay เป็น Tailscale `100.118.43.30`
- build/test Go ผ่านทั้ง collector และ processor แล้ว restart สำเร็จ
- self-test `pipeline-selftest-20260722` ผ่าน raw Cowrie -> pending retry -> Mongo upsert -> `event:canonical`
- self-test ยืนยัน numeric `network.dst_port`, canonical document และ Redis pending กลับเป็น 0
- self-test พบ Mongo operator หลุดระหว่าง patch (`bson.M{"": doc}`), แก้เป็น ``, rebuild และยืนยัน retry recovery สำเร็จ
- ณ เวลาตรวจ: Zeek, collector, processor และ Cowrie เป็น active ทั้งหมด

## งานต่อเนื่องที่ยังไม่รัน

- ไม่ได้ลบ collection เก่าหรือ self-test document
- ยังไม่ import Cowrie rotated logs และไม่ลบ log test เดิม
- ขั้นถัดไปคือเพิ่ม dead-letter policy/เครื่องมือ backfill แล้วทดสอบ event จริงจาก bot ภายนอกผ่าน Tailscale


## 5. ZeroTier retained (user correction)

- ผู้ใช้ยืนยันว่า ZeroTier ยังใช้งานอยู่ จึงเพิ่ม `worker-zerotier0` กลับเข้า Zeek โดยดัก `ztxoocdlsi`
- network `633e31d8a21076ea` (`Rasb-PI`) สถานะ `OK`, IP `10.58.33.42/24`
- Zeek ดักพร้อมกันสาม interface: `wlan0`, `tailscale0`, `ztxoocdlsi`
- Collector แยกยอมรับ Tailscale (`100.118.43.30`) และ ZeroTier (`10.58.33.42`) โดยไม่ใช้ตัวแปรปลายทางเดียวทับกัน
- คืน `10.58.33.0/24` เข้า `ALLOW_CIDRS` และเพิ่ม `SENSOR_ZEROTIER_IP`/`SENSOR_ZEROTIER_IFACE`
- build/test collector ผ่าน; deploy Zeek และ restart collector สำเร็จ; worker ทั้งสามเป็น `running`
- ข้อความก่อนหน้าในหัวข้อ 1 ที่ระบุว่านำ ZeroTier ออกจาก production ถูกยกเลิกโดยหัวข้อนี้
