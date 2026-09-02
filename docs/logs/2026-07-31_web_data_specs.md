# Web Dashboard Data Specs (Data Dictionary)

เอกสารนี้สรุปโครงสร้างข้อมูล (Schema) ทั้งหมดที่ระบบ Honeypot Pipeline ของเราผลิตออกมา ซึ่งฝั่ง **Web Dashboard (Next.js)** สามารถดึงไปใช้วาดกราฟหรือทำตารางได้เลยครับ โดยแบ่งออกเป็น 2 แหล่งหลักคือ **MongoDB (สำหรับดูประวัติย้อนหลัง)** และ **Redis (สำหรับดึงสดแบบ Real-time)**

---

## 🟢 1. ข้อมูลการโจมตี (Honeypot Events)
ข้อมูลส่วนนี้ได้มาจากการดักจับของ **Zeek** (Network) และ **Cowrie** (SSH/Telnet) ซึ่งผ่านการ Normalize และ Enrich (เสริมข้อมูล) มาให้เรียบร้อยแล้ว

**แหล่งดึงข้อมูล:**
* **MongoDB:** Database `honeypot_db` -> Collection `events`
* **Redis:** Stream `event:enriched` (หากต้องการดึงสดผ่าน WebSocket)

**โครงสร้างข้อมูล (JSON Schema):**
```json
{
  "event_id": "string (UUID เฉพาะของแต่ละ Event)",
  "timestamp": "Date (เวลาที่เกิดเหตุการณ์)",
  "source": "string (ระบุแหล่งที่มา: 'cowrie', 'zeek:conn', 'zeek:ssh', 'zeek:ssl')",
  "event_type": "string (ประเภท: 'ssh_login', 'ssh_attempt', 'connection', 'command_execution')",
  
  // ข้อมูลเครือข่ายพื้นฐาน (มีทุก Event)
  "network": {
    "src_ip": "string (IP ของแฮกเกอร์)",
    "dst_ip": "string (IP ของเครื่อง Honeypot)",
    "src_port": "string/number",
    "dst_port": "string/number",
    "protocol": "string (tcp, udp, icmp)"
  },

  // ข้อมูลพิกัดภูมิศาสตร์ (เอาไว้วาดแผนที่)
  "geo": {
    "country": "string (เช่น 'TH', 'US', 'CN')",
    "city": "string",
    "lat": "number (ละติจูด)",
    "lon": "number (ลองจิจูด)"
  },

  // ข้อมูลพฤติกรรมเชิงลึก (มักจะมีเฉพาะของ Cowrie)
  "activity": {
    "command": "string (คำสั่งที่แฮกเกอร์พิมพ์ เช่น 'uname -a', 'wget ...')",
    "username": "string (ชื่อ User ที่ใช้ล็อคอิน เช่น 'root', 'admin')",
    "password": "string (รหัสผ่านที่แฮกเกอร์สุ่มเดาเข้ามา)",
    "filename": "string (ชื่อไฟล์ที่แฮกเกอร์พยายามอัปโหลดหรือดาวน์โหลด)",
    "ttylog": "string (Session Log ID สำหรับไปดูวิดีโอย้อนหลัง)"
  },

  // ข้อมูลภัยคุกคามเชิงลึก (Threat Intel)
  "threat_intel": {
    "ja3": "string (ลายเซ็น SSL Client)",
    "hassh": "string (ลายเซ็น SSH Client)",
    "tags": ["array ของ string (เช่น 'malicious', 'scanner', 'brute-forcer')"]
  }
}
```

---

## 🔵 2. ข้อมูลสถานะเครื่อง (Hardware Metrics)
ข้อมูลส่วนนี้คือสถิติการใช้ทรัพยากรของเครื่อง Raspberry Pi อัปเดตทุกๆ 30 วินาที เหมาะสำหรับทำหน้าปัด (Gauge) และกราฟเส้น (Line Chart)

**แหล่งดึงข้อมูล:**
* **MongoDB:** Database `honeypot_db` -> Collection `hardware_metrics`
* **Redis:** Stream `raw:hardware`

**โครงสร้างข้อมูล (JSON Schema):**
```json
{
  "timestamp": "Date (เวลาที่บันทึกค่า)",
  
  // 🌡️ อุณหภูมิ
  "temperature": "float (องศาเซลเซียส เช่น 61.15)",

  // 🧠 CPU (ค่าทั้งหมดเป็นเปอร์เซ็นต์ %)
  "cpu_percent": "float (โหลดรวมทั้งหมด เช่น 15.42)",
  "cpu_cores": "number (จำนวนคอร์ เช่น 4)",
  "cpu_core_0_percent": "float (โหลดแยกเฉพาะ Core 0)",
  "cpu_core_1_percent": "float",
  
  // 💾 RAM (หน่วยเป็น Bytes ทั้งหมด)
  "mem_percent": "float (เปอร์เซ็นต์ที่ใช้ไป เช่น 23.03)",
  "mem_total_bytes": "number (RAM ทั้งหมด เช่น 8322752512)",
  "mem_used_bytes": "number (RAM ที่กำลังใช้งาน)",
  "mem_free_bytes": "number (RAM ที่ว่างแบบเพียวๆ)",
  "mem_available_bytes": "number (RAM ที่ว่างรวม Cache)",

  // 💽 Storage (ความจุฮาร์ดดิสก์/SD Card)
  "disk_percent": "float (เปอร์เซ็นต์ที่ใช้ไป เช่น 28.35)",
  "disk_total_bytes": "number",
  "disk_used_bytes": "number",
  "disk_free_bytes": "number",

  // 🌐 Network (แบนด์วิดท์เข้า/ออก)
  "net_bytes_recv": "number (จำนวน Bytes ที่รับเข้ามาทั้งหมด)",
  "net_bytes_sent": "number (จำนวน Bytes ที่ส่งออกไปทั้งหมด)",
  "net_packets_recv": "number (จำนวนแพ็กเกจที่รับ)",
  "net_packets_sent": "number (จำนวนแพ็กเกจที่ส่ง)"
}
```

---

## 💡 ไอเดียสำหรับทำหน้าเว็บ Dashboard
ฝั่ง Frontend (Next.js) สามารถหยิบข้อมูลเหล่านี้ไปออกแบบ UI ได้ดังนี้:

1. **Live Attack Map:** ดึง `geo.lat`, `geo.lon`, และ `network.src_ip` ไปพล็อตบนแผนที่โลก (เช่นใช้ไลบรารี Mapbox หรือ React Simple Maps)
2. **Top Passwords/Usernames:** Group By ฟิลด์ `activity.password` และ `activity.username` เพื่อทำกราฟแท่ง (Bar Chart) โชว์รหัสผ่านยอดฮิตที่แฮกเกอร์ใช้โจมตี
3. **Command Execution Log:** ดึง `activity.command` มาทำตารางสีดำๆ คล้ายๆ Terminal เพื่อโชว์คำสั่งที่แฮกเกอร์พิมพ์แบบ Real-time
4. **Pi Health Monitor:** นำ `cpu_percent`, `mem_percent`, และ `temperature` มาทำหน้าปัดกลมๆ (Gauge Chart) เพื่อเฝ้าระวังไม่ให้บอร์ดพัง
5. **Network Traffic:** นำ `net_bytes_recv` มาลบกับค่าก่อนหน้า (Delta) เพื่อคำนวณความเร็วเน็ต (Bandwidth Mbps) แล้ววาดเป็นกราฟเส้นคลื่น (Area Chart)
