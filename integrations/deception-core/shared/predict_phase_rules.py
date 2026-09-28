import re
import sys

# ==============================================================================
# RULE DEFINITIONS FOR CYBER KILL CHAIN PHASES
# ==============================================================================
# กฎตรวจจับเฟสโจมตีโดยใช้ Regular Expressions
# เรียงลำดับจากเฟสท้ายๆ ขึ้นมาต้นๆ เพื่อป้องกันคำสั่งทั่วไปทับซ้อนกับเป้าหมายการขโมยข้อมูล
RULES = [
    # 7. Actions on Objectives (เน้นไฟล์ความลับ, แฟลชไดร์ฟ, ฐานข้อมูล)
    {
        "phase": "Actions_on_Objectives",
        "patterns": [
            r"nas_mount\.conf",
            r"\.env",
            r"config\.php",
            r"db_replica_prod\.sql",
            r"financial_statement",
            r"backup_exfil",
            r"tar -czf.*backup",

            # --- เพิ่มสำหรับ persona ใหม่ (Odoo/PostgreSQL) ---
            r"\.pgpass",
            r"odoo\.conf",
            r"pg_hba\.conf",
            r"bank_reconciliation",
            r"sales_pipeline_export",
            r"stock_valuation_report",
            r"odoo_production.*\.sql\.gz",
            r"odoo_debug_dump",
            r"pg_dump",
            # SELECT ที่ดึงข้อมูลจากตารางที่มีข้อมูลจริง (ไม่นับ \dt/\d/\l ซึ่งเป็นแค่การสำรวจโครงสร้าง)
            r"SELECT\s+.*\s+FROM\s+(res_partner|res_users|res_company|account_move|sale_order|stock_quant|hr_employee|ir_config_parameter)",
        ]
    },
    # 6. Command and Control (เน้นการเชื่อมต่อกลับ, shell, ping เซิร์ฟเวอร์ร้าย)
    {
        "phase": "Command_and_Control",
        "patterns": [
            r"nc\s+.*",
            r"/dev/tcp/",
            r"socket\.socket",
            r"malicious-c2\.net"
        ]
    },
    # 5. Installation (เน้นการสร้าง backdoor ทิ้งไว้ถาวร, แก้ไขสิทธิ์, cronjob)
    {
        "phase": "Installation",
        "patterns": [
            r"crontab",
            r"/etc/sudoers",
            r"\.bashrc",
            r"/etc/rc\.local",
            r"sysupdate",
            r"authorized_keys",
            r"\.ssh/"
        ]
    },
    # 4. Exploitation (เน้นการสั่งรันโค้ดอันตราย, ยกระดับสิทธิ์)
    {
        "phase": "Exploitation",
        "patterns": [
            r"\./.*\.elf",
            r"python3?\s+.*backdoor\.py",
            r"(sh|bash|\./)\s*exploit\.sh",
            r"\./local_exp",
            r"sudo\s+\./",
            r"perl\s+.*exploit.*"
        ]
    },
    # 3. Delivery (เน้นการโหลดไฟล์เข้ามาในระบบ)
    {
        "phase": "Delivery",
        "patterns": [
            r"wget\s+.*",
            r"curl\s+.*",
            r"scp\s+.*"
        ]
    },
    # 2. Weaponization (เน้นการเขียนโค้ดเตรียมบุกรุก หรือการคอมไพล์)
    {
        "phase": "Weaponization",
        "patterns": [
            r"gcc\s+.*",
            r"exploit\.c",
            r"exploit\.sh",
            r"\.tmp_lock",
            r"\.setup\.sh",
            r"msfvenom"
        ]
    },
    # 1. Reconnaissance (เน้นคำสั่งสำรวจข้อมูลระบบทั่วไป)
    {
        "phase": "Reconnaissance",
        "patterns": [
            r"^whoami$",
            r"^pwd$",
            r"^uname(\s+.*)?$",
            r"^ip(\s+.*)?$",
            r"^ifconfig(\s+.*)?$",
            r"^df(\s+.*)?$",
            r"^history$",
            r"^ls(\s+.*)?$",
            r"^id(\s+.*)?$",
            r"netstat",
            r"lsof",
            r"cat\s+/etc/passwd",
            r"cat\s+/etc/issue",
            r"cat\s+/etc/shadow",
            r"cat\s+.*note\.txt",
            r"cat\s+os-release",

            # --- เพิ่มสำหรับ persona ใหม่: สำรวจโครงสร้าง DB ใน psql ยังนับเป็น
            #     recon-level เท่านั้น (ไม่ใช่ Actions_on_Objectives) เพราะแค่ดูว่า
            #     มีตารางอะไรบ้าง/โครงสร้างคอลัมน์ ไม่ได้ดึงข้อมูลจริงออกมา
            r"^\\dt$",
            r"^\\d\s+\S+",
            r"^\\l$",
            r"^hostname$",
        ]
    }
]

def predict_command_phase(command):
    cmd_clean = command.strip()

    # วนลูปเช็กว่าคำสั่งตรงกับกฎของเฟสใด
    for rule in RULES:
        for pattern in rule["patterns"]:
            if re.search(pattern, cmd_clean, re.IGNORECASE):
                return rule["phase"], 100.0  # มั่นใจ 100% เพราะตรงกฎพอดี

    # หากไม่ตรงกับเฟสโจมตีใดๆ เลย ปัดเป็น Normal/Unknown
    return "Normal/Safe", 100.0

# ==============================================================================
# STATEFUL SESSION PHASE TRACKER
# ==============================================================================
class SessionPhaseTracker:
    # 7 Lockheed Martin Cyber Kill Chain phases ordered by progression
    PHASE_ORDER = [
        "Reconnaissance",
        "Weaponization",
        "Delivery",
        "Exploitation",
        "Installation",
        "Command_and_Control",
        "Actions_on_Objectives"
    ]

    def __init__(self, initial_phase="Reconnaissance"):
        self.current_phase = initial_phase
        self.history = []

    def update(self, command):
        """
        วิเคราะห์คำสั่งใหม่และอัปเดตเฟสของเซสชัน
        เฟสจะเคลื่อนไปข้างหน้า (ก้าวหน้าขึ้น) หรือคงที่เท่านั้น ไม่มีการถอยหลัง
        """
        predicted_phase, _ = predict_command_phase(command)

        # ถ้าจับได้ว่าเป็นคำสั่งทั่วไป (Normal/Safe) ไม่ต้องปรับระดับเฟส ให้คงเฟสเดิมไว้
        if predicted_phase == "Normal/Safe":
            self.history.append((command, predicted_phase, self.current_phase))
            return self.current_phase

        try:
            current_idx = self.PHASE_ORDER.index(self.current_phase)
            predicted_idx = self.PHASE_ORDER.index(predicted_phase)

            # เลื่อนเฟสไปข้างหน้าเฉพาะเมื่อคำสั่งใหม่มีระดับเฟสที่สูงกว่าเฟสปัจจุบัน
            if predicted_idx > current_idx:
                self.current_phase = predicted_phase
        except ValueError:
            pass

        self.history.append((command, predicted_phase, self.current_phase))
        return self.current_phase

def main():
    # ตรวจสอบการรับค่าผ่าน Argument
    if len(sys.argv) > 1:
        command = " ".join(sys.argv[1:])
        phase, conf = predict_command_phase(command)
        print(f"\nCommand: '{command}'")
        print(f"Predicted Phase (Rule-based): {phase} (Confidence: {conf}%)")
        print()
        return

    # แสดงโหมดอินเตอร์แอคทีฟ (Stateful Tracking)
    tracker = SessionPhaseTracker()
    print("=" * 60)
    print(" Stateful Cyber Kill Chain - Session Phase Tracker ")
    print("=" * 60)
    print("Enter commands sequentially to see the session phase progress.")
    print("Type 'exit' to quit.\n")

    try:
        while True:
            command = input("hacker@target$ ").strip()
            if not command:
                continue
            if command.lower() in ["exit", "quit"]:
                break

            cmd_phase, _ = predict_command_phase(command)
            session_phase = tracker.update(command)

            print(f"--> Command Phase : \033[1;33m{cmd_phase}\033[0m")
            print(f"--> Session Phase : \033[1;32m{session_phase}\033[0m (Feeds into Qwen System Prompt)")
            print("-" * 50)
    except KeyboardInterrupt:
        print("\nExiting...")

if __name__ == "__main__":
    main()
