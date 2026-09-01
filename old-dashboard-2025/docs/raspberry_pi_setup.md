## ติดตั้ง Raspberry Pi Imager
https://www.raspberrypi.com/software/

<img width="1165" height="592" alt="image" src="https://github.com/user-attachments/assets/4e8eb530-bcaa-4b16-9609-224b2cf2238f" />

## ติดตั้ง Ubuntu server (24.04.3 LTS)
<img width="690" height="489" alt="image" src="https://github.com/user-attachments/assets/9e0029a7-61f2-4177-8725-8e4b1bcb7495" />
<img width="403" height="393.5" alt="image" src="https://github.com/user-attachments/assets/388ad81c-18ec-48c8-a099-89b82b76aa14" />
<img width="366.5" height="390.5" alt="image" src="https://github.com/user-attachments/assets/0766f778-380d-4fb4-b479-e623283b344a" />

## เข้าผ่าน SSH 
ผ่าน cmd (10.35.68.99)
```
ssh <username>@<ip_address>
```

## Setup Ubuntu
```
sudo apt update
sudo apt upgrade
```
### ปรับแต่ง ssh
```
sudo nano /etc/ssh/sshd_config
```
เปลี่ยนจาก
#Port 22  -> Port 2222
```
sudo systemctl restart ssh
sudo reboot
```
เข้าใหม่ด้วย
```
ssh <username>@<ip_address> -p 2222
```

## เพิ่ม sensor forwarder สำหรับส่ง Cowrie ไป GCP

---

### ขั้นที่ 0: ตรวจเตรียม (ทำก่อน Pi)

1. **เช็ค GCP VM running:**
    ```bash
    # บน GCP VM หรือ Cloud Shell
    systemctl status honeypot-ingest-api
    systemctl status honeypot-dashboard-api
    systemctl status honeypot-session-worker
    systemctl status honeypot-enrichment-worker
    systemctl status honeypot-analysis-worker
    ```
    ทั้งหมดต้อง active (running)

2. **เตรียม bearer token จาก GCP:**
    - ขอจาก GCP admin หรือ `cat ~/.honeypot/api_tokens.json`

3. **หา Pi IP / public IP:**
    ```bash
    Pi$ hostname -I  # เพื่อ GCP firewall rules
    ```

---

### ขั้นที่ 1: Copy production module ไป Pi

**บน development machine (ที่นี่):**
```bash
# หรือ git clone/pull ถ้า Pi มี git access
scp -r /home/cpe27/dashboard-honeypot/server/plugin/production \
   pi-user@<pi-ip>:/tmp/production-backup
```

**บน Pi:**
```bash
Pi$ cp -r /tmp/production-backup /home/cpe27/dashboard-honeypot/server/plugin/production
Pi$ ls -la /home/cpe27/dashboard-honeypot/server/plugin/production/
```

ต้องมี:
- `__init__.py`
- `config.py`
- `serialization.py`
- `sensor_forwarder.py` (main forwarder)
- `test_connection.py`
- `setup.sh`
- `honeypot-forwarder-main.env.example`
- `README.md`

---

### ขั้นที่ 2: รัน setup.sh (automated setup)

**บน Pi:**
```bash
Pi$ sudo chmod +x /home/cpe27/dashboard-honeypot/server/plugin/production/setup.sh
Pi$ sudo /home/cpe27/dashboard-honeypot/server/plugin/production/setup.sh
```

setup.sh จะทำต่อไปนี้อัตโนมัติ:
- สร้าง `honeypot-forwarder` system user
- สร้าง `/etc/honeypot-forwarder` config directory (mode 755)
- Copy `honeypot-forwarder-main.env.example` → `/etc/honeypot-forwarder/main.env` (mode 600)
- สร้าง `/var/lib/honeypot-forwarder` spool directory (mode 700, owner honeypot-forwarder)
- ตรวจสอบ cowrie.json readable โดย honeypot-forwarder
- เพิ่ม honeypot-forwarder ไปใน cowrie group ถ้าต้อง

**Output คาดหวัง:**
```
==========================================
Honeypot Sensor Forwarder Setup
==========================================
[Step 1] Creating honeypot-forwarder system user
✓ User honeypot-forwarder created

[Step 2] Creating configuration directory...
✓ Config directory created

[Step 3] Installing configuration template
✓ Configuration template installed to /etc/honeypot-forwarder/main.env
⚠ EDIT THIS FILE: sudo nano /etc/honeypot-forwarder/main.env

[Step 4] Creating spool directory...
✓ Spool directory created with correct permissions

[Step 5] Checking Cowrie log file...
✓ Cowrie log file found

[Step 6] Checking file permissions
Cowrie log owner: cowrie:cowrie
✓ User honeypot-forwarder can read /home/cowrie/cowrie/var/log/cowrie/cowrie.json

[Step 7] Setup Summary
...
```

---

### ขั้นที่ 3: Edit configuration

**บน Pi:**
```bash
Pi$ sudo nano /etc/honeypot-forwarder/main.env
```

Edit ค่าต่อไปนี้:

```bash
# ⚠️ REQUIRED: แทนที่ด้วย GCP bearer token
HONEYPOT_API_TOKEN=<INSERT_YOUR_GCP_TOKEN_HERE>

# ⚠️ REQUIRED: ตรวจสอบ path ถูก
COWRIE_LOG_PATH=/home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

ถ้าหา cowrie.json path ไม่เจอ:
```bash
Pi$ sudo find / -name "cowrie.json" 2>/dev/null
```

บันทึก: Ctrl+X → Y → Enter

---

### ขั้นที่ 4: Test configuration

**บน Pi:**
```bash
Pi$ export PYTHONPATH=/home/cpe27/dashboard-honeypot/server/plugin
Pi$ python3 -m production.test_connection
```

**Output คาดหวัง:**
```
==========================================
Honeypot Sensor Forwarder - Connection Test
==========================================
[1/5] Testing configuration loading...
   ✓ Config loaded successfully
      Sensor ID: pi5-cowrie-01
      Ingest URL: http://34.124.181.196:8080/events
      ...

[2/5] Testing Cowrie log accessibility...
   ✓ Cowrie log readable: /home/cowrie/cowrie/var/log/cowrie/cowrie.json
      First event: {"eventid": "cowrie.client.version", ...

[3/5] Testing spool directory setup...
   ✓ Spool directory writable: /var/lib/honeypot-forwarder

[4/5] Testing network connectivity to GCP ingest_api...
   ✓ GCP ingest_api health check: OK (HTTP 200)
   Testing event submission...
   ✓ Connection successful (HTTP 202 Accepted)
      Response: {"accepted": 1, "stored": 1}

[5/5] Testing API token configuration...
   ⚠ WARNING: Using test token (unsafe for production)

==========================================
Results: 5/5 checks passed
==========================================
✓ All checks passed! Ready for deployment.
```

ถ้ามี ✗ error:
- `Permission denied` → ตรวจสอบ group: `id honeypot-forwarder`
- `Connection failed` → ตรวจสอบ firewall: `curl -v http://34.124.181.196:8080/health`
- `HTTP 401` → ตรวจสอบ token ถูกต้อง

---

### ขั้นที่ 5: Test --once mode (ทดสอบ 1 รอบ)

**บน Pi:**
```bash
Pi$ export PYTHONPATH=/home/cpe27/dashboard-honeypot/server/plugin
Pi$ sudo -u honeypot-forwarder env $(sudo cat /etc/honeypot-forwarder/main.env | xargs) \
      python3 -m production.sensor_forwarder --once
```

**Output:**
```json
{"sent": 5, "remaining": 0, "error": "", "timestamp": "2026-05-13T12:34:56.123456+00:00"}
```

✓ ถ้า `"error": ""` และ `"sent" > 0` → OK  
✗ ถ้า error message → ตรวจสอบ token, network, GCP firewall

---

### ขั้นที่ 6: Verify GCP received data

**บน GCP VM หรือ Cloud Shell:**

Check ingest_api logs:
```bash
GCP$ journalctl -u honeypot-ingest-api -n 20 --no-pager

# ต้องเห็น POST /events จาก Pi IP
```

Check sessions created:
```bash
GCP$ curl http://127.0.0.1:8081/sessions | jq '.' | head -20

# หรือ query database
GCP$ psql production << 'SQL'
SELECT session_id, payload_json, updated_at
FROM sessions
ORDER BY updated_at DESC
LIMIT 5;
SQL
```

Check if reports generated:
```bash
GCP$ curl http://127.0.0.1:8081/reports | jq '.' | head -10
```

---

### ขั้นที่ 7: Create systemd service file

**บน Pi:**
```bash
Pi$ sudo nano /etc/systemd/system/honeypot-sensor-forwarder-main.service
```

Copy from template:
```bash
Pi$ sudo cp /home/cpe27/dashboard-honeypot/server/plugin/production/honeypot-sensor-forwarder-main.service.template \
      /etc/systemd/system/honeypot-sensor-forwarder-main.service

Pi$ sudo nano /etc/systemd/system/honeypot-sensor-forwarder-main.service
```

ตรวจสอบ:
- `EnvironmentFile=/etc/honeypot-forwarder/main.env` ✓ (ไม่ใส่ token ตรง ๆ)
- `WorkingDirectory=/home/cpe27/dashboard-honeypot/server/plugin` ✓
- `Environment=PYTHONPATH=/home/cpe27/dashboard-honeypot/server/plugin` ✓
- `ExecStart=/usr/bin/python3 -m production.sensor_forwarder` ✓
- `User=honeypot-forwarder` ✓

บันทึก: Ctrl+X → Y → Enter

---

### ขั้นที่ 8: Enable and start service

**บน Pi:**
```bash
Pi$ sudo systemctl daemon-reload
Pi$ sudo systemctl enable honeypot-sensor-forwarder-main.service
Pi$ sudo systemctl start honeypot-sensor-forwarder-main.service

# ตรวจสอบสถานะ
Pi$ sudo systemctl status honeypot-sensor-forwarder-main.service
```

**Output:**
```
● honeypot-sensor-forwarder-main.service - Honeypot Sensor Forwarder...
    Loaded: loaded (/etc/systemd/system/honeypot-sensor-forwarder-main.service; enabled)
    Active: active (running) since Tue 2026-05-13 12:00:00 UTC; 2s ago
    Process: 1234 ExecStart=/usr/bin/python3 -m production.sensor_forwarder
    Main PID: 1234
```

---

### ขั้นที่ 9: Monitor logs

**บน Pi:**
```bash
Pi$ sudo journalctl -u honeypot-sensor-forwarder-main -f
```

**Output (continuous):**
```json
May 13 12:00:01 pi-server honeypot-forwarder-main[1234]: {"service": "sensor_forwarder", "sent": 5, "remaining": 0, "error": "", "timestamp": "2026-05-13T12:00:01.123456+00:00"}
May 13 12:00:06 pi-server honeypot-forwarder-main[1234]: {"service": "sensor_forwarder", "sent": 3, "remaining": 0, "error": "", "timestamp": "2026-05-13T12:00:06.234567+00:00"}
May 13 12:00:11 pi-server honeypot-forwarder-main[1234]: {"service": "sensor_forwarder", "sent": 0, "remaining": 0, "error": "", "timestamp": "2026-05-13T12:00:11.345678+00:00"}
```

Press Ctrl+C to stop monitoring

---

### ขั้นที่ 10: Configure GCP Firewall

**บน GCP Cloud Console หรือ Cloud Shell:**

Allow only Pi IP to reach ingest_api:
```bash
GCP$ gcloud compute firewall-rules create allow-pi-to-ingest-api \
   --allow=tcp:8080 \
   --source-ranges=<PI_PUBLIC_IP>/32 \
   --target-tags=gcp-ingest-api \
   --direction=INGRESS
```

**สำคัญ:**
- ใส่ Pi IP ที่ได้จากขั้น 0.3
- Bearer token authentication ยังคงต้องใช้ (firewall เป็นชั้นป้องกันเพิ่มเติม)
- ไม่ใช้ `0.0.0.0/0` ในระบบ production

---

### ข้อ จำกัดและหมายเหตุ

**Current Limitations:**
1. **cowrie.json เท่านั้น:** Standard Cowrie events เท่านั้น
    - cowrie_custom.json ยังไม่ส่ง (pending schema review)
2. **Parallel pipeline:** ไม่กระทบ Cowrie → SQLite → Dashboard ที่มีอยู่
3. **No local processing:** ทุกอย่าง analyze บน GCP side
4. **Resilience:** Events queue ใน spool ถ้า GCP down, auto-replay เมื่อ recover

**Security:**
- เปลี่ยน `HONEYPOT_API_TOKEN` จาก test value ก่อน production
- ไม่ใส่ token ใน systemd service file (ใช้ EnvironmentFile แทน)
- Restrict firewall ให้เฉพาะ Pi IP

ส่วนนี้เป็น pipeline แยกจากของเดิม โดยไม่กระทบ Cowrie -> SQLite -> Dashboard ที่มีอยู่

**สรุป:** Cowrie ส่ง cowrie.json → production.sensor_forwarder ประมวลผลและส่งไปยัง GCP ingest_api พร้อมกับที่ Honeypot_Log_Processor.py ส่งไป SQLite เพื่อ Dashboard

### เตรียม: ตั้งค่าผู้ใช้ honeypot-forwarder และ spool directory

**ขั้นที่ 1:** สร้างผู้ใช้ระบบ honeypot-forwarder (จำกัดสิทธิ์)
```bash
sudo useradd -m -s /usr/sbin/nologin honeypot-forwarder
```

**ขั้นที่ 2:** สร้าง spool directory และตั้งค่า permissions
```bash
sudo mkdir -p /var/lib/honeypot-forwarder
sudo chown honeypot-forwarder:honeypot-forwarder /var/lib/honeypot-forwarder
sudo chmod 700 /var/lib/honeypot-forwarder
```

**ขั้นที่ 3:** ตรวจสอบว่า honeypot-forwarder สามารถอ่าน cowrie.json ได้
```bash
# หาตำแหน่ง Cowrie log
ls -la /home/cowrie/cowrie/var/log/cowrie/cowrie.json

# ตรวจสอบสิทธิ์ read
su - honeypot-forwarder -c "head -1 /home/cowrie/cowrie/var/log/cowrie/cowrie.json"
```
ถ้าได้ error เรื่อง permission ให้เพิ่ม honeypot-forwarder ไปในกลุ่ม cowrie:
```bash
sudo usermod -aG cowrie honeypot-forwarder
# จากนั้น logout และ login ใหม่ เพื่อให้ group changes มีผล
```

---

### ขั้นที่ 1: สร้าง systemd service

สร้างไฟล์ `honeypot-sensor-forwarder-main.service`:
```bash
sudo nano /etc/systemd/system/honeypot-sensor-forwarder-main.service
```

วางเนื้อหาต่อไปนี้:
```ini
[Unit]
Description=Honeypot Sensor Forwarder (Forward Cowrie logs to GCP)
After=network-online.target cowrie.service
Wants=network-online.target
Requires=cowrie.service

[Service]
Type=simple
User=honeypot-forwarder
Group=honeypot-forwarder

# Environment variables for production.sensor_forwarder
Environment=HONEYPOT_API_TOKEN=<INSERT_GCP_API_TOKEN_HERE>
Environment=INGEST_URL=http://34.124.181.196:8080/events
Environment=SENSOR_ID=pi5-cowrie-01
Environment=COWRIE_LOG_PATH=/home/cowrie/cowrie/var/log/cowrie/cowrie.json
Environment=FORWARDER_SPOOL_PATH=/var/lib/honeypot-forwarder/sensor_spool.ndjson
Environment=PYTHONPATH=/home/cpe27/dashboard-honeypot/server/plugin

# Run the production.sensor_forwarder in tail-mode (continuous polling)
# Deployed in: /home/cpe27/dashboard-honeypot/server/plugin/production/
ExecStart=/opt/honeypot/.venv/bin/python -m production.sensor_forwarder

Restart=always
RestartSec=5

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=honeypot-forwarder

[Install]
WantedBy=multi-user.target
```

**หมายเหตุ:** 
- บรรทัด `HONEYPOT_API_TOKEN=<INSERT_GCP_API_TOKEN_HERE>` ต้องแทนที่ด้วย bearer token จริงจาก GCP
- ตรวจสอบว่า `After=network-online.target cowrie.service` ตรงกับชื่อ service ของ Cowrie จริงบน Pi (ถ้าไม่ชื่อ `cowrie.service` ให้แก้ให้ตรง ไม่งั้น dependency อาจไม่ทำงาน)
- Path `/opt/honeypot/.venv/bin/python` คือตำแหน่งของ virtual environment ที่มี `production.sensor_forwarder` module

---

### ขั้นที่ 2: Validation Steps (ทดสอบก่อนเปิดใช้งาน)

**ทดสอบ A: ตรวจสอบการเชื่อมต่อและการส่ง --once**
```bash
# รัน --once เพื่อดูว่า forwarder ทำงานและเชื่อมต่อ GCP ได้หรือไม่
sudo -u honeypot-forwarder /opt/honeypot/.venv/bin/python -m production.sensor_forwarder --once

# ต้องเห็น output ประมาณนี้:
# {"sent": X, "remaining": Y, "error": "", "timestamp": "2026-05-13T..."}
```
หากได้ error:
- ตรวจสอบ network connectivity: `ping 34.124.181.196`
- ตรวจสอบ firewall rules บน GCP VM
- ตรวจสอบ bearer token ถูกต้องหรือไม่

**ทดสอบ B: ตรวจสอบว่า GCP ingest_api ได้รับข้อมูลและ HTTP 202 ถูกตัดสินใจ**

บน GCP VM (หรือใช้ Cloud Shell):
```bash
# ตรวจสอบ ingest_api logs เพื่อดูว่าได้รับ POST request หรือไม่
# (วิธีที่แน่นอนขึ้นอยู่กับวิธี deploy ของ GCP)
# ตัวอย่างเช่น:
journalctl -u ingest_api -f  # ถ้า ingest_api เป็น systemd service
# หรือ
docker logs <ingest_api_container>  # ถ้า ingest_api ใน Docker
```

**ทดสอบ C: ตรวจสอบว่า GCP backend สร้าง sessions/jobs/reports แล้ว**

บน GCP database (ผ่าน psql หรือ application client):
```sql
-- ตรวจสอบว่ามี session ใหม่จาก sensor_id=pi5-cowrie-01 หรือไม่
SELECT COUNT(*) FROM sessions WHERE sensor_id = 'pi5-cowrie-01';

-- ตรวจสอบ jobs (analysis/enrichment)
SELECT COUNT(*) FROM jobs WHERE sensor_id = 'pi5-cowrie-01' AND created_at > NOW() - INTERVAL '5 minutes';

-- ตรวจสอบ reports
SELECT COUNT(*) FROM reports WHERE sensor_id = 'pi5-cowrie-01' AND created_at > NOW() - INTERVAL '5 minutes';
```

ถ้าได้ 0 records:
- ตรวจสอบ event payload format ตรงกับ GCP schema หรือไม่
- ตรวจสอบ GCP backend workers (session_worker, enrichment_worker, analysis_worker) กำลังรันหรือไม่
- ตรวจสอบ ingest_api logs เพื่อดูข้อความ error

**ทดสอบ D: ตรวจสอบ spool และ tail-mode**
```bash
# ตรวจสอบว่า spool file มีข้อมูลเก่าจากการทดสอบ --once หรือไม่
ls -la /var/lib/honeypot-forwarder/
cat /var/lib/honeypot-forwarder/sensor_spool.ndjson | head -3
```

---

### ขั้นที่ 3: เปิดใช้งาน systemd service (หลังจากทดสอบ validation สำเร็จแล้ว)

```bash
sudo systemctl daemon-reload
sudo systemctl enable honeypot-sensor-forwarder-main.service
sudo systemctl start honeypot-sensor-forwarder-main.service

# ตรวจสอบสถานะ
sudo systemctl status honeypot-sensor-forwarder-main.service

# ดู logs
sudo journalctl -u honeypot-sensor-forwarder-main -f
```

---

### ขั้นที่ 4: ตั้งค่า GCP Firewall (อนุญาตเฉพาะ Pi ไป GCP port 8080)

บน GCP Cloud Console หรือ gcloud CLI:
```bash
# ตัวอย่าง: อนุญาตเฉพาะ IP ของ Pi
# (แทนที่ PI_PUBLIC_IP ด้วย IP แท้จริงของ Pi)
gcloud compute firewall-rules create allow-pi-to-ingest-api \
  --allow=tcp:8080 \
  --source-ranges=<PI_PUBLIC_IP>/32 \
  --target-tags=gcp-ingest-api \
  --direction=INGRESS

# หรือ ถ้ามี Pi หลายตัวหรือ range ให้ใช้:
gcloud compute firewall-rules create allow-pi-range-to-ingest-api \
  --allow=tcp:8080 \
  --source-ranges=<PI_NETWORK_RANGE/24> \
  --target-tags=gcp-ingest-api \
  --direction=INGRESS
```

**สำคัญ:** 
- Firewall rules เป็นเพียงชั้นป้องกันเพิ่มเติม Bearer token authentication ยังคงต้องเปิดใช้งาน
- ไม่ควรใช้ `0.0.0.0/0` ในระบบ production (ห้ามให้ใคร ๆ เข้าถึงได้)

---

### ขั้นที่ 5: Security Hardening

**เปลี่ยน API Token:**
```bash
sudo nano /etc/systemd/system/honeypot-sensor-forwarder-main.service
```
แก้ไขบรรทัด:
```ini
Environment=HONEYPOT_API_TOKEN=<ACTUAL_SECURE_TOKEN_FROM_GCP>
```
บันทึก → reload service:
```bash
sudo systemctl daemon-reload
sudo systemctl restart honeypot-sensor-forwarder-main.service
```

---

### หมายเหตุและข้อ จำกัด

1. **cowrie.json เท่านั้น (ระหว่างนี้):**
   - ใช้เฉพาะ `cowrie.json` (standard Cowrie events) ที่ส่งไป GCP ingest_api
   - ยังไม่ส่ง `cowrie_custom.json` จนกว่าจะตรวจ eventid/schema กับ GCP ให้เรียบร้อย

2. **Pipeline ที่มีอยู่ไม่เปลี่ยน:**
   - `Cowrie → Honeypot_Log_Processor.py → SQLite → Node/Prisma → WebSocket → Dashboard` ยังทำงานแยกต่างหากอย่างเดิม
   - `sensor_forwarder` อ่านจาก cowrie.json เพียงอย่างเดียว ไม่แทรกแซงใด ๆ ลงในระบบเดิม

3. **GCP side architecture:**
   - ฝั่ง GCP ยังรัน ingest_api, dashboard_api, session_worker, enrichment_worker, analysis_worker เท่านั้น
   - ไม่มี Pi-side processing นอกเหนือจากการส่งข้อมูลผ่าน forwarder

4. **ความสำคัญของ Spool:**
   - ถ้า GCP ingest_api down ขณะ Pi กำลังส่ง forwarder จะเก็บข้อมูลใน `/var/lib/honeypot-forwarder/sensor_spool.ndjson`
   - เมื่อ ingest_api ฟื้นคืน forwarder จะส่ง backlog โดยอัตโนมัติ (replay)

