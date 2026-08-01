# Raspberry Pi 5 Honeypot Maintenance Log

วันที่: 22 กรกฎาคม 2026  
เครื่อง: `ubuntu-pi-server`  
ระบบ: Ubuntu 24.04.4 LTS, ARM64  
Kernel: `6.8.0-1060-raspi`

## วัตถุประสงค์

- ตรวจสอบ Hailo AI HAT+ 2 (Hailo-10H) หลังติดตั้ง driver 5.3.0
- ตรวจสอบ service และ network exposure ของระบบ honeypot ที่รับช่วงมาจากทีมเดิม
- ลบของเก่าที่ไม่ใช้งาน
- จำกัดพอร์ตของ LLM runtime ไม่ให้เปิดสู่ network โดยไม่จำเป็น
- เก็บ Cowrie, MySQL honeypot และ data pipeline เดิมให้ทำงานต่อ

## 1. ตรวจสอบ Hailo-10H

ผลการตรวจสอบ: ทำงานปกติ

- ระบบพบอุปกรณ์ PCIe ที่ `0000:01:00.0`
- Device architecture: `HAILO10H`
- Kernel driver: `hailo1x`
- Kernel module: `hailo1x_pci`
- HailoRT CLI: 5.3.0
- PCIe driver/DKMS: 5.3.0
- Firmware: 5.3.0
- `hailortcli scan` และ `fw-control identify` ติดต่ออุปกรณ์สำเร็จ
- อุณหภูมิขณะ idle ประมาณ 50–50.5°C
- แรงดันขณะตรวจประมาณ 798 mV
- Hailo runtime ไม่มี systemd service แยก ซึ่งเป็นพฤติกรรมปกติ

ไฟล์ `.hef` คือโมเดลที่ compile สำหรับ Hailo แล้ว สามารถรันผ่าน HailoRT ได้ ไม่จำเป็นต้องพึ่ง Ollama แต่แอป LLM ยังต้องมีส่วนจัดการ prompt, tokenizer, generation และ API อยู่

## 2. Service inventory ที่พบ

ระบบ honeypot หลัก:

- `cowrie.service` — Cowrie SSH/Telnet honeypot
- `honeypot-collector.service` — อ่าน log เข้า Redis
- `honeypot-hardware.service` — ส่ง system metrics เข้า Redis
- `honeypot-processor.service` — ประมวลผล Redis แล้วเขียน MongoDB Atlas
- `honeypot-sensor-forwarder.service` — ส่ง Cowrie events ไป GCP ผ่าน Tailscale
- `redis-server.service` — Redis ภายในเครื่อง
- `honeypot-disk-monitor.timer` — ตรวจพื้นที่ทุกชั่วโมง

LLM/MySQL honeypot:

- `llm-mysql.service` — MySQL honeypot ที่พอร์ต 3306
- `llama-server.service` — llama.cpp API ที่พอร์ต 8080
- Docker container `ollama` — Ollama API ที่พอร์ต 11434

Remote networking:

- `tailscaled.service`
- `zerotier-one.service`

## 3. ความสัมพันธ์ระหว่าง Cowrie และ LLM เดิม

ตรวจแล้ว Cowrie ไม่ได้เรียก Llama หรือ Ollama โดยตรง

```text
Cowrie :22/:23
    -> cowrie.json
    -> collector -> Redis -> processor -> MongoDB Atlas
    -> sensor-forwarder -> GCP

MySQL client :3306
    -> llm_mysql.py
    -> localhost:8080/completion
    -> llama_mysql_v3.gguf ผ่าน llama.cpp
```

- Cowrie ไม่มี dependency กับ `llama-server.service` หรือ `llm-mysql.service`
- LLM เดิมใช้กับ MySQL honeypot เท่านั้น
- การปิด Llama/MySQL honeypot ในอนาคตจะไม่ทำให้ Cowrie หยุด
- Ollama container ไม่ได้เกี่ยวกับ Cowrie หรือ `llm_mysql.py`

## 4. รายการที่ลบแล้ว

### Snap ngrok

- ถอน snap `ngrok`
- ยืนยันว่าไม่มี ngrok process หรือ listener ค้าง
- Snap สร้าง data snapshot อัตโนมัติก่อนถอน

### บัญชี `madethai`

- ตรวจแล้วไม่มี process หรือ service ใช้งานบัญชีนี้
- ลบบัญชีและ home directory `/home/madethai`
- SSH authorized key ของบัญชีถูกลบพร้อม home
- ไม่พบไฟล์ของ UID เดิมอยู่นอก home

### Dashboard converter เก่า

- Disable และลบ `python_script.service`
- ลบ symlink ที่ใช้ start ตอน boot
- เคลียร์ failed state ของ systemd
- Service นี้เสียอยู่ก่อนแล้ว เพราะ directory ของ dashboard ถูกลบไปแล้ว

### SQLite honeypot เก่า

- ลบ `/home/cpe27/HeneyPot.db` ขนาดประมาณ 42 MB
- ไม่ลบ SQLite ที่เป็น internal state ของ Codex, VS Code, Copilot หรือ Gemini
- MongoDB ปัจจุบันเป็น MongoDB Atlas และ processor เชื่อมผ่าน `mongodb+srv`

## 5. SSH และบัญชีผู้ดูแล

- SSH จริงสำหรับผู้ดูแลฟังที่พอร์ต `2222`
- Cowrie ใช้พอร์ต `22` และ `23`
- ปิด root login
- ปิด password authentication
- ใช้ public key authentication
- SSH keys ทั้ง 3 รายการใน `/home/cpe27/.ssh/authorized_keys` ได้รับการยืนยันว่าเป็นของทีมพัฒนาปัจจุบัน จึงเก็บไว้ทั้งหมด

## 6. ZeroTier และ Tailscale

### ZeroTier ปัจจุบัน

- Network name: `Rasb-PI`
- Network ID: `633e31d8a21076ea`
- Interface: `ztxoocdlsi`
- IP: `10.58.33.42/24`

ลบกฎ UFW เก่าที่อ้างถึง:

- Interface `zttqhz5xog`
- Subnet `10.123.100.0/24`

เก็บกฎ wildcard `zt+` สำหรับ SSH พอร์ต 2222 เพื่อให้ครอบคลุม interface ZeroTier ปัจจุบัน

### Tailscale ปัจจุบัน

- Tailnet: `sentalize981@gmail.com`
- เครื่องนี้: `pi5-cowrie-01`
- Tailscale IP: `100.118.43.30`
- GCP ingest host: `100.122.213.37`

Sensor forwarder ส่ง events ไปที่ GCP ผ่าน Tailscale โดยใช้ API token ซึ่งไม่ได้บันทึกค่าจริงไว้ในเอกสารนี้

## 7. Firewall/UFW

ก่อนแก้ไข เครื่องมี UFW config เก่าค้างอยู่ แต่ package `ufw` ถูกถอนออก และ INPUT policy เปิดกว้าง

สิ่งที่ดำเนินการ:

- ติดตั้ง UFW 0.36.2-6
- เปิด UFW และตั้งให้เริ่มตอน boot
- Default incoming: deny
- Default outgoing: allow
- Default routed: deny
- การติดตั้ง UFW ถอน `iptables-persistent` และ `netfilter-persistent` เนื่องจาก package conflict
- กฎ UFW และ custom rules ที่จำเป็นยังเก็บใน `/etc/ufw/`

พอร์ตสำคัญหลังตั้งค่า:

- `22/tcp` — Cowrie SSH: เปิด
- `23/tcp` — Cowrie Telnet: เปิด
- `3306/tcp` — LLM MySQL honeypot: เปิด
- `2222/tcp` — SSH ผู้ดูแล: จำกัดตาม LAN/Tailscale/ZeroTier rules
- `2224/tcp` — Cowrie listener สำหรับ GCP ผ่าน Tailscale
- `8080/tcp` — บล็อกจากภายนอก
- `11434/tcp` — bind เฉพาะ localhost

### บล็อก Llama API พอร์ต 8080 ก่อน Tailscale

Tailscale สร้าง `ts-input` ไว้ก่อน UFW ทำให้ UFW deny ปกติอาจถูกข้ามจาก tailnet จึงเพิ่มกฎโดยตรงเป็นลำดับแรกของ INPUT ทั้ง IPv4/IPv6:

```text
INPUT ! -i lo tcp dport 8080 -> DROP
```

สร้างไฟล์เพื่อให้กฎกลับมาหลัง reboot:

- `/usr/local/sbin/honeypot-local-firewall-rules`
- `/etc/systemd/system/honeypot-local-firewall.service`

สถานะ service: enabled และ active

ผลลัพธ์:

- ภายนอก, LAN, Tailscale และ ZeroTier เข้า 8080 ไม่ได้
- `llm_mysql.py` ยังเรียก `127.0.0.1:8080` ได้
- Llama health endpoint ตอบ `{"status":"ok"}`

## 8. จำกัด Docker Ollama

ก่อนแก้ไข:

```text
0.0.0.0:11434 -> ollama container
[::]:11434    -> ollama container
```

Docker port publishing สามารถข้าม UFW บางกรณีได้ จึง recreate container โดยเก็บ named volume เดิม และเปลี่ยน host binding เป็น:

```text
127.0.0.1:11434 -> container:11434
```

ค่าที่รักษาไว้:

- Container name: `ollama`
- Restart policy: `unless-stopped`
- Volume: `ollama:/root/.ollama`
- โมเดล: `gemma:2b-instruct-q4_0` ขนาดประมาณ 1.7 GB

ผลลัพธ์:

- Ollama ใช้งานได้จาก Pi ผ่าน localhost
- LAN/Tailscale/ZeroTier/Internet เรียกพอร์ต 11434 โดยตรงไม่ได้
- ข้อมูลโมเดลไม่สูญหาย

## 9. Credential status

- MongoDB เป็น Atlas ของเจ้าของระบบเดิมตั้งแต่ก่อนรับช่วง ไม่ได้เปลี่ยน credential
- Redis อยู่ที่ `127.0.0.1:6379` และยังไม่มี password
- Honeypot API token อยู่ใน `/etc/honeypot/honeypot.env`
- MongoDB/Redis config อยู่ใน `/etc/honeypot-agent.env`
- ไม่มีการบันทึก secret จริงในเอกสารนี้

หาก rotate API token ในอนาคต ต้องเพิ่ม token ใหม่ที่ GCP receiver ก่อน เปลี่ยน token บน Pi ทดสอบ event แล้วจึงถอน token เก่า

## 10. สถานะสุดท้าย

- Hailo-10H: ปกติ
- UFW: active/enabled
- Custom pre-Tailscale firewall: active/enabled
- Cowrie: active
- MySQL LLM honeypot: active
- llama-server: active และเข้าจาก localhost เท่านั้นในทางปฏิบัติ
- Ollama: active และ bind เฉพาะ localhost
- Redis/pipeline agents: active
- Tailscale: active
- ZeroTier: active
- systemd failed services: 0
- Disk: ประมาณ 81 GB ว่างจาก 117 GB ณ เวลาตรวจ

## 11. งานที่แนะนำต่อ

1. เลือกว่าจะเก็บ MySQL LLM honeypot หรือย้ายไป Hailo-10H
2. หากไม่ใช้ Ollama ให้หยุดและลบ container พร้อมพิจารณาลบ volume/model เพื่อคืนพื้นที่อีกประมาณ 1.7 GB
3. ทบทวนนโยบาย outbound ของ Cowrie ให้ชัดว่าจะห้ามทั้งหมด หรืออนุญาต public Internet แต่ห้าม private network
4. ตรวจ MongoDB Atlas Network Access และจำกัด IP/CIDR เท่าที่ทำได้
5. พิจารณาเพิ่ม Redis authentication แม้ Redis จะ bind เฉพาะ localhost
6. ทดสอบ firewall จากเครื่องอื่นใน LAN, Tailscale และ ZeroTierหลัง reboot
7. ทดสอบ Hailo inference ด้วยไฟล์ `.hef` สำหรับ Hailo-10H

## 12. ปรับ Hardware Agent ให้เก็บ Network Throughput

ปรับ source และ deploy `honeypot-hardware.service` ใหม่แล้ว โดยเปลี่ยนจาก
การรวม counters ของทุก network interface เป็นการเก็บแยกเฉพาะ:

- `wlan0` — physical/uplink interface และ primary throughput
- `tailscale0` — overlay traffic สำหรับ management และ external bot/service

ไม่รวม `lo`, `docker0`, `veth*` และ ZeroTier ใน production defaults
เนื่องจาก overlay traffic วิ่งผ่าน `wlan0` อยู่แล้ว จึงห้ามนำ throughput ของ
`wlan0` กับ `tailscale0` มาบวกกัน เพราะจะนับข้อมูลซ้ำ

ค่า configuration ที่ agent รองรับ:

```ini
NETWORK_INTERFACES=wlan0,tailscale0
NETWORK_PRIMARY_INTERFACE=wlan0
NETWORK_SAMPLE_SECONDS=30
```

เพิ่ม metrics ต่อ interface:

- cumulative RX/TX bytes และ packets
- RX/TX bytes per second
- RX/TX Mbps
- RX/TX packets per second
- RX/TX errors และ dropped packets
- interface up/down
- sample interval ตามเวลาจริง

เก็บ field เดิม `net_bytes_sent`, `net_bytes_recv`,
`net_packets_sent` และ `net_packets_recv` เพื่อ compatibility แต่เปลี่ยน
ความหมายให้เป็น counters ของ primary physical interface (`wlan0`) เท่านั้น
แทนการรวมทุก interface

รอบแรกหลัง restart จะส่งเฉพาะ counters เพราะยังไม่มี previous sample
ตั้งแต่รอบที่สองจึงคำนวณ throughput และหาก interface counter reset จะข้าม rate
หนึ่งรอบเพื่อป้องกันกราฟกระโดด

ผลตรวจหลัง deploy:

- `gofmt`, `go test ./...` และ ARM64 build สำเร็จ
- restart `honeypot-hardware.service` สำเร็จ
- agent และ processor active
- Redis `raw:hardware` ได้ field throughput ใหม่ครบ
- sample ที่ตรวจมี interval 30.006 วินาที
- `wlan0` RX 0.037589 Mbps และ TX 0.088036 Mbps
- `tailscale0` เป็น 0 Mbps ในช่วงตรวจ เนื่องจากไม่มี traffic ใน sample นั้น
- ไม่มี systemd failed service เพิ่มจากการเปลี่ยนแปลง

เอกสาร schema และวิธี build อยู่ที่:

```text
/home/cpe27/honeypot-pipeline/agents/hardware-agent/README.md
```

## คำสั่งตรวจสอบสั้น ๆ

```bash
# Hailo
hailortcli scan
hailortcli fw-control identify
timeout 5s hailortcli monitor

# Services
systemctl --failed
systemctl status cowrie honeypot-processor honeypot-sensor-forwarder

# Firewall
sudo ufw status verbose
sudo iptables -S INPUT
sudo ip6tables -S INPUT

# Ports
sudo ss -lntup

# Containers
docker ps
docker exec ollama ollama list

# Overlay networks
tailscale status
sudo zerotier-cli listnetworks
```
