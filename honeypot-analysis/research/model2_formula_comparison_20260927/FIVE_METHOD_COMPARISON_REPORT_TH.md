# ผลเปรียบเทียบ Model1 + Model2 จำนวน 5 วิธี (Controlled Synthetic PoC)

## คำตัดสิน

ผลรอบนี้เป็น `CONTROLLED_SYNTHETIC_POC_NOT_REAL_WORLD_ACCURACY` เท่านั้น ชุด SEALED_FINAL มี 120 แถวจาก 30 procedure families ซึ่งแยก family จาก FIT/SELECTION แต่ label ยังอยู่ใน corpus ไฟล์เดียวกัน ไม่ใช่ blind holdout ที่ฝากไว้กับบุคคลอิสระ ดังนั้นใช้ตัดสินกลไก PoC ได้ แต่ห้ามเขียนว่าเป็นความแม่นยำบนทราฟฟิกจริง

ในชุดนี้ **Model1 + Model2 ใหม่ 54F + Weighted Voting ได้ผลดีที่สุด**: Hit@1 = 0.8750, MRR = 0.8750 และ nDCG@5 = 0.8508 อย่างไรก็ตามยังไม่ประกาศเป็น production winner เพราะไม่มี paired field evaluation ที่ independently adjudicated ทั้ง Weighted Voting และ Gated Weighted Reciprocal-Rank จึงถูกเก็บไว้พร้อมกันเพื่อเปรียบเทียบต่อ โดยหน้า live/PDF ต้องเรียกทั้งสองว่า advisory late-fusion ไม่ใช่ probability/confidence และไม่ใช้เลือก response อัตโนมัติ

## Artifact ที่ใช้

| ส่วน | Identity |
|---|---|
| Model1 S1 LinearSVC package | `3bad72d688add1064aa236f3a24e9f031aa9e97a8fb449ad730e64389487c5d7` |
| Model2 เก่า 32F | `104d4c77a3e1536b847561abb19fc7c0d6d7dc0111cd98d1ff2d9c9d74a2ed1a` |
| Model2 ใหม่ 54F V3 | `fb56940ba2ca90c0942813168d9f5a85cb80a58da5c62e2dd7e343da5f71d5fa` |
| 54F feature schema | `28cc1a43e59259c5939dacdb889cdbe4e13fbdaa71b197264e27907a071d13c1` |

Model1 ใช้ top-k ต่อคำสั่งจาก artifact จริง ส่วน Model2 ทั้งสองรุ่นรับ episode เดียวกันและให้ผลแยกต่อ T1105/T1046/T1110 คะแนนดิบของโมเดลทั้งสองไม่ถูกบวกกัน

## สูตรที่เปรียบเทียบ

Weighted Voting:

`S_vote(t) = 0.5 × I(t เป็น candidate ของ Model1) + 0.5 × G2(t)`

Gated Weighted Reciprocal-Rank:

`S_rr(t) = 1.0 × [(1/N) × Σc I(t ∈ Lc)/(60 + rc(t))] + 0.25 × [G2(t)/(60 + 1)]`

โดย `G2(t)=1` เฉพาะ Model2 ให้ PRESENT และผ่าน identity/evidence gate; Model2 สร้าง candidate ใหม่ไม่ได้ และ ABSENT ไม่หักคะแนน

## ผลทั้ง 5 วิธี

| วิธี | Hit@1 | MRR | nDCG@5 | Relevant candidate coverage |
|---|---:|---:|---:|---:|
| 1. Model1-only | 0.1875 | 0.4844 | 0.5561 | 0.8750 |
| 2. Model1 + Model2 เก่า 32F + Weighted Voting | 0.6563 | 0.7656 | 0.7696 | 0.8750 |
| 3. Model1 + Model2 เก่า 32F + Gated Weighted Reciprocal-Rank | 0.5313 | 0.7031 | 0.7177 | 0.8750 |
| 4. Model1 + Model2 ใหม่ 54F + Weighted Voting | **0.8750** | **0.8750** | **0.8508** | 0.8750 |
| 5. Model1 + Model2 ใหม่ 54F + Gated Weighted Reciprocal-Rank | 0.7500 | 0.8125 | 0.7984 | 0.8750 |

มี positive sessions 64 แถวและ negative controls 56 แถว Candidate coverage ไม่เปลี่ยน เพราะทุกวิธีอนุญาตเฉพาะ candidate จาก Model1 การเพิ่ม Model2 จึงเปลี่ยนลำดับเท่านั้น ไม่ได้แก้กรณี Model1 ไม่มี TTP จริงอยู่ใน top-k

## Model2 raw decisions

| รุ่น | T1105 TP/FP/TN/FN/U | T1046 TP/FP/TN/FN/U | T1110 TP/FP/TN/FN/U |
|---|---|---|---|
| เก่า 32F | 29/0/36/19/36 | 20/0/64/0/36 | 16/0/68/0/36 |
| ใหม่ 54F V3 | 48/4/68/0/0 | 20/0/100/0/0 | 16/0/104/0/0 |

`U` คือ unavailable ตาม contract ไม่ถูกแปลงเป็น ABSENT รุ่น 54F ยังมี T1105 false positives 4/72 negatives จึงไม่ควรอ้างว่า model quality ผ่าน real-world gate

## การแก้ T1110

เพิ่ม hard-negative 12 แถวใน SEALED_FINAL ซึ่งมี login success หนึ่งครั้งร่วมกับ transfer, discovery หรือ command mix แต่ไม่มี repeated failed authentication ผล 54F ใหม่ให้ T1110 ABSENT ครบ 12/12 และ gate ฝั่ง ensemble กำหนดเพิ่มว่า T1110 จะโหวตได้เมื่อ `auth_failure_count >= 2` และ `auth_max_failure_streak >= 2` เท่านั้น ดังนั้น login success เดี่ยวไม่สามารถดัน T1110 แม้ raw modelรุ่นใดทาย PRESENT

Gate นี้เป็น evidence eligibility ไม่ได้แก้หรือลบ raw prediction ผู้วิเคราะห์ยังตรวจ raw result ได้ และต้องไม่ตีความว่า login สำเร็จหนึ่งครั้งคือ Brute Force (T1110)

## ข้อจำกัดและสถานะใช้งาน

- Weighted Voting เป็นผู้นำเฉพาะ controlled synthetic set นี้
- Gated Weighted Reciprocal-Rank ยังเก็บไว้เป็น comparator ตามสูตรในรายงาน
- ระบบต้องแสดงทั้งสอง order จนมี paired field evaluation ก่อนเลือก production winner
- Model2 ยังคงเป็น non-authoritative shadow; ห้ามสร้าง canonical finding หรือสั่ง response
- คะแนนทั้งสองสูตรเป็น ordinal advisory score ไม่ใช่ probability/confidence
- Model2 32F ที่ไม่มี Zeek flow เป็น unavailable และ fallback ไป Model1-only

ผล machine-readable อยู่ใน `FIVE_METHOD_COMPARISON_RESULT.v1.json` และโค้ด reproducible อยู่ใน `compare.py`
