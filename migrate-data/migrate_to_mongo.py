import sqlite3
import json
from pymongo import MongoClient

# ================= 1. CONFIGURATION =================
# ระบุที่อยู่ไฟล์ SQLite ของเดิม (ระวังชื่อไฟล์ HeneyPot.db สะกดตามของเดิมเป๊ะๆ)
SQLITE_DB_PATH = './HeneyPot.db'

# ใส่ Connection String ของ MongoDB Atlas
MONGO_URI = "mongodb+srv://siridet_db:73VhsuDHlKiI0hh0@honeypotdb.rm64xom.mongodb.net/?appName=HoneypotDB"
MONGO_DB_NAME = "HoneypotDB"

# ================= 2. CONNECT TO DATABASES =================
print("🔌 Connecting to databases...")
sqlite_conn = sqlite3.connect(SQLITE_DB_PATH)
# ตั้งค่าให้ดึงชื่อคอลัมน์ออกมาด้วย (เพื่อแปลงเป็น Dictionary ง่ายๆ)
sqlite_conn.row_factory = sqlite3.Row 
cursor = sqlite_conn.cursor()

mongo_client = MongoClient(MONGO_URI)
mongo_db = mongo_client[MONGO_DB_NAME]

# ================= 3. MIGRATION FUNCTIONS =================
def migrate_table(table_name, mongo_collection_name, json_columns):
    print(f"📦 Migrating '{table_name}' to MongoDB collection '{mongo_collection_name}'...")
    
    try:
        cursor.execute(f"SELECT * FROM {table_name}")
        rows = cursor.fetchall()
        
        if not rows:
            print(f"   - No data found in '{table_name}'. Skipping.")
            return

        documents = []
        for row in rows:
            doc = dict(row) # แปลง SQL Row เป็น Python Dictionary
            
            # 🔥 ไม้ตาย: แปลง Text ที่เป็น JSON กลับไปเป็น Object
            for col in json_columns:
                if doc.get(col):
                    try:
                        doc[col] = json.loads(doc[col])
                    except json.JSONDecodeError:
                        pass # ถ้าไม่ใช่ JSON ที่สมบูรณ์ ก็เก็บเป็น Text ไว้เหมือนเดิม
            
            # ลบ ID เดิมของ SQLite ทิ้ง เพื่อให้ MongoDB สร้าง _id แบบ ObjectId ขึ้นมาเอง
            if 'id' in doc:
                del doc['id']
                
            documents.append(doc)
            
        # ยัดข้อมูลทั้งหมดลง MongoDB รวดเดียว (Batch Insert)
        if documents:
            mongo_db[mongo_collection_name].insert_many(documents)
            print(f"   ✅ Successfully migrated {len(documents)} records!")
            
    except sqlite3.OperationalError as e:
        print(f"   ❌ Error reading table '{table_name}': {e}")

# ================= 4. EXECUTE MIGRATION =================
if __name__ == "__main__":
    # ย้ายข้อมูล Cowrie (ดึงฟิลด์ json_data กลับเป็น Object)
    migrate_table(
        table_name="honeypot_logs", 
        mongo_collection_name="cowrie_logs", 
        json_columns=["message", "json_data"]
    )
    
    # ย้ายข้อมูล OpenCanary (ดึงฟิลด์ logdata_raw และ full_json_line กลับเป็น Object)
    migrate_table(
        table_name="opencanary_logs", 
        mongo_collection_name="opencanary_logs", 
        json_columns=["logdata_raw", "logdata_msg_logdata", "full_json_line"]
    )
    
    # ถ้ามีตารางอื่นที่อยากย้ายด้วย (เช่น users) สามารถเพิ่มบรรทัดนี้ได้เลย
    # migrate_table("users", "dashboard_users", [])

    print("🎉 All migrations completed successfully!")
    sqlite_conn.close()
    mongo_client.close()
