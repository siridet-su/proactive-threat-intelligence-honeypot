# คู่มือติดตั้งระบบ Honeypot: เตรียมพื้นฐานเครื่อง Pi

- **สถานะเอกสาร:** ฉบับร่างสำหรับทดสอบบน VM ยังไม่รับรองสำหรับติดตั้งบนเครื่องใช้งานจริง
- **เป้าหมาย:** Ubuntu Server 24.04 LTS, ARM64 (`aarch64`)
- **ขอบเขต:** ระบบปฏิบัติการ เครื่องมือพื้นฐาน และการตรวจสอบก่อนติดตั้งบริการ Honeypot
- **ปรับปรุงล่าสุด:** 25 กันยายน 2026

## 1. วัตถุประสงค์

ใช้เตรียม VM สำหรับตรวจสอบสภาพแวดล้อมและ dependency พื้นฐานของเครื่อง Pi ก่อนติดตั้งบริการจริง ทุกคำสั่งที่เปลี่ยนแปลงแพ็กเกจให้ทดลองบน VM หลังสร้าง snapshot เท่านั้น

## 2. ขอบเขต

ดำเนินการเฉพาะการตรวจ Ubuntu, สถาปัตยกรรมระบบ, systemd, เวลา, พื้นที่จัดเก็บ และแพ็กเกจพื้นฐานที่อาจจำเป็น

ระยะนี้ยังไม่ติดตั้ง Cowrie, Zeek, Docker/Compose, Redis, MongoDB, PostgreSQL/Deception Core, Web-corp, OpenCanary หรือ legacy sensor-forwarder และยังไม่เปลี่ยน firewall, SSH, service account หรือ ACL

ไม่ติดตั้ง Go toolchain บน Pi; ให้สร้าง Go agents บนเครื่องสำหรับ build แล้วนำ binary ที่ตรวจสอบแล้วไปใช้ในระยะถัดไป

## 3. ข้อกำหนด VM

1. ใช้ไฟล์ `ubuntu-24.04.5-live-server-arm64.iso` จากเว็บไซต์ทางการ: https://cdimages.ubuntu.com/ubuntu/releases/24.04.5/release/
2. ตรวจค่า SHA-256 ของ ISO เทียบกับไฟล์ `SHA256SUMS` ใน release directory ก่อนบูต
3. ใช้สถาปัตยกรรมของ guest เป็น ARM64/AArch64 จริง หากเครื่อง host เป็น x86-64 ต้องใช้ตัวจำลอง ARM64 เช่น QEMU; guest แบบ AMD64 ใช้ยืนยันเป้าหมาย ARM64 ไม่ได้
4. จัดสรรเบื้องต้น 2 vCPU, RAM 4 GiB และ disk 32 GiB สำหรับทดสอบการติดตั้งเท่านั้น ไม่ใช่ข้อกำหนดประสิทธิภาพของ Pi
5. ใช้ NAT และคงช่องทาง console/recovery ไว้ ห้าม bridge เข้ากับ public หรือ production network
6. ติดตั้ง Ubuntu Server แบบ minimal สร้างผู้ดูแลระบบที่ไม่ใช่ root และไม่เลือกติดตั้งบริการของโครงการ
7. หลังบูตครั้งแรก ก่อนเปลี่ยนแพ็กเกจ ให้สร้าง snapshot ชื่อ `00-ubuntu-24.04-arm64-clean`

หมายเหตุ: ISO นี้เป็น image ARM64 ทั่วไปสำหรับ VM ไม่ได้จำลอง firmware หรืออุปกรณ์เฉพาะของ Raspberry Pi การทดสอบบนฮาร์ดแวร์จริงยังเป็นขั้นตอนแยกต่างหาก

## 4. ขั้นตอนตรวจสอบและติดตั้ง

### 4.1 ตรวจ baseline ของระบบ

รันจาก console ของ VM หรือช่องทางบริหารที่แยกจากเครือข่ายสาธารณะ:

```sh
grep -E '^(ID|VERSION_ID)=' /etc/os-release
uname -m
dpkg --print-architecture
systemctl --version | head -n 1
apt-get --version | head -n 1
dpkg-query --version | head -n 1
timedatectl show -p NTPSynchronized --value
df -h /
df -i /
free -h
systemctl --failed --no-pager
ss -lntup
```

ค่าที่คาดหวังคือ Ubuntu `24.04`, architecture `aarch64`/`arm64` และมี systemd, apt กับ dpkg-query หาก architecture ไม่ตรงหรือพบ service/listener ที่อธิบายไม่ได้ ให้หยุดและตรวจสอบก่อนดำเนินการต่อ

### 4.2 ตรวจโปรไฟล์ติดตั้งของโครงการ

เมื่อมี checkout ของ revision ที่อนุมัติอยู่ใน VM แล้ว ให้รันจาก repository root:

```sh
python3 scripts/pti_install.py preflight --profile deploy/profiles/pi-host-foundation-ubuntu-2404-arm64.json
python3 scripts/pti_install.py package-audit --profile deploy/profiles/pi-host-foundation-ubuntu-2404-arm64.json
python3 scripts/pti_install.py plan --profile deploy/profiles/pi-host-foundation-ubuntu-2404-arm64.json
```

คำสั่งเหล่านี้เป็นการตรวจแบบอ่านอย่างเดียว: ตรวจความเข้ากันได้ อ่านสถานะแพ็กเกจจาก dpkg และแสดงแผนเท่านั้น ไม่ติดตั้งแพ็กเกจหรือเปลี่ยนบริการ ค่า `install_enabled=false` และรายการเงื่อนไขที่ยังไม่ผ่านเป็นผลที่คาดหมาย

### 4.3 ตรวจและติดตั้งแพ็กเกจพื้นฐานที่เสนอไว้

แพ็กเกจต่อไปนี้เป็นรายการที่เสนอให้พิจารณา ต้องตรวจสถานะและแหล่งที่มาของแพ็กเกจบน VM ก่อน:

| แพ็กเกจ | วัตถุประสงค์ |
|---|---|
| `ca-certificates` | ตรวจสอบ TLS ของแหล่ง artifact ที่อนุมัติ |
| `curl` | ตรวจ endpoint หรือดาวน์โหลด artifact ตามขั้นตอนที่อนุมัติ |
| `git` | ดึง source revision ที่ผ่านการทบทวน หากจำเป็น |
| `python3` | runtime candidate สำหรับทดสอบ Cowrie รุ่นที่ pin ไว้ |
| `python3-venv` | สร้าง Python virtual environment สำหรับการทดสอบ Cowrie |

หลังบันทึก baseline และยืนยัน snapshot แล้ว จึงปรับปรุงเฉพาะ package index และตรวจ version/source:

```sh
sudo apt-get update
apt-cache policy ca-certificates curl git python3 python3-venv
```

หากผู้ดูแลยอมรับแหล่งแพ็กเกจและ version แล้ว ให้ติดตั้งเฉพาะรายการนี้บน VM ทดสอบ:

```sh
sudo apt-get install --no-install-recommends ca-certificates curl git python3 python3-venv
```

ห้ามใช้ `full-upgrade`, `dist-upgrade`, repository ภายนอกที่ยังไม่ทบทวน หรือชุด compiler ขนาดใหญ่ในขั้นตอนนี้ คำสั่ง `apt-get update` ปรับปรุงดัชนีแพ็กเกจ แต่ไม่ได้อัปเกรดแพ็กเกจที่ติดตั้งอยู่

ตรวจผลหลังติดตั้ง:

```sh
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Status}\n' ca-certificates curl git python3 python3-venv
python3 --version
python3 -m venv --help >/dev/null
```

บันทึกเลขรุ่นและแหล่งที่มาของแพ็กเกจจาก `apt-cache policy` ผลจาก VM เท่านั้นที่ใช้ตัดสินใจรับรองรายการแพ็กเกจได้

### 4.4 ตรวจสุขภาพและการเปิดพอร์ต

```sh
timedatectl show -p NTPSynchronized --value
df -h /
df -i /
systemctl --failed --no-pager
systemctl list-units --type=service --state=running --no-pager
ss -lntup
ip -brief address
ip route
```

บันทึกบริการที่ทำงานผิดพลาด พอร์ตที่เปิดรอรับการเชื่อมต่อ เวลาไม่ตรง หรือพื้นที่ disk/inode ต่ำที่ยังอธิบายไม่ได้ ห้ามเปลี่ยน SSH หรือ firewall เพียงเพื่อให้ผลตรวจตรงตามคาด และต้องคงช่องทางกู้คืนผ่าน console ไว้

## 5. งานที่ต้องทดสอบหรืออนุมัติแยก

- **ZeroTier:** ยังไม่ติดตั้งระหว่าง clean baseline ให้เลือกวิธีติดตั้งหลังตรวจ VM แล้วเท่านั้น หากทดสอบ ให้ใช้ test network แยกและให้ผู้ดูแล join/authorize เอง ห้ามบันทึก network ID, node identity หรือ credential ใน Git
- **Cowrie:** ยังไม่ติดตั้ง service ต้องทดสอบ pinned revision, dependency lock และ patch series ก่อน
- **Zeek:** ยังไม่ติดตั้ง service ต้องยืนยัน ARM64 package และแก้ความต่างของ install prefix กับ systemd unit ก่อน
- **บัญชีและสิทธิ์ไฟล์ของบริการ:** ยังไม่สร้างบัญชี directory หรือ ACL จนกว่าจะอนุมัติตารางสิทธิ์ของแต่ละบริการ
- **Docker, database และ web:** อยู่นอกขอบเขตระยะนี้

## 6. เกณฑ์ผ่านและการย้อนกลับ

ถือว่าผ่านขั้นเตรียมพื้นฐานเครื่องเมื่อยืนยัน Ubuntu 24.04 ARM64, systemd และช่องทางกู้คืนได้ บันทึกข้อมูลระบบ เวลา พื้นที่จัดเก็บ และพอร์ตที่เปิดไว้แล้ว ตรวจแหล่งที่มาและเลขรุ่นของแพ็กเกจครบ และไม่มีบริการของโครงการที่เปิดใช้งานโดยไม่ตั้งใจ

หากผลติดตั้งหรือทดสอบทำให้สถานะ VM ไม่ชัดเจน ให้ย้อนกลับไปยัง snapshot `00-ubuntu-24.04-arm64-clean` ห้ามใช้ `apt autoremove` หรือการลบ directory ด้วยตนเองแทนการกู้คืน snapshot

## 7. ข้อมูลสำหรับบันทึกผลทดสอบ

บันทึกวันทดสอบ, VM snapshot, revision ของ repository, OS/architecture, package version/origin, ผล preflight, service/listener ที่พบ, ปัญหาและวิธีแก้ โดยไม่บันทึก token, credential, node identity, raw event หรือข้อมูลเครือข่ายที่ไม่จำเป็น

**สถานะสุดท้าย:** คู่มือนี้เป็นฉบับร่างก่อนทดสอบ ต้องปรับให้ตรงกับผลจริงบน VM ก่อนนำไปใช้กับ Raspberry Pi
