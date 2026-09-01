# ModernBERT-based Command Classifier — LIVE STATE

> สถานะเอกสาร: `LIVE STATE` — เอกสารนี้เป็นข้อมูลสถานะปัจจุบันที่แก้ไขต่อเนื่องได้ ไม่ใช่ artifact แบบ immutable/versioned  
> ปรับปรุงล่าสุด: 2026-08-31 (Asia/Bangkok)  
> หลักฐานล่าสุดที่ใช้ยืนยัน: SecureBERT deep review วันที่ 2026-08-29 และการตรวจ integration ใน repo หลักวันที่ 2026-08-31  
> ขอบเขต: โมเดลจำแนกคำสั่ง Cowrie ที่โปรเจกต์เรียกย้อนหลังว่า “SecureBERT”

## สรุปสั้น

คอมโพเนนต์ที่โปรเจกต์เรียกว่า SecureBERT เป็น private checkpoint ของ
`ModernBertForSequenceClassification` ซึ่งถูกปรับให้จำแนก command fragment ไปยัง
MITRE ATT&CK top-level Technique จำนวน 196 classes ไม่ใช่โมเดล SecureBERT แบบ
RoBERTa-based masked-language model ที่เผยแพร่สาธารณะ

หน้าที่ของโมเดลคือเสนอ `TTP candidate + raw softmax score` เพื่อช่วยยืนยันหรือชี้
ความขัดแย้งกับ deterministic rules เท่านั้น โมเดลไม่มีอำนาจสร้าง trusted TTP หรือ
canonical truth ด้วยตัวเอง

การตรวจ repo หลักเพิ่มเติมไม่เปลี่ยนข้อสรุปเรื่อง inference ของตัวโมเดล แต่ทำให้เห็นว่า
ตัวโมเดลเป็นเพียง stage หนึ่งใน production pipeline ที่ยาวกว่า ได้แก่ authenticated
ingest, canonical persistence, session reconstruction, command splitting, rule/model
comparison, authority decision, trust gate และการสร้าง trusted tactic phases

คำเรียกที่ปลอดภัยและตรงข้อเท็จจริงคือ:

> A private project fine-tuned ModernBERT sequence classifier, historically named
> SecureBERT, that proposes one ATT&CK technique candidate per Cowrie command
> fragment.

## 1. เหตุผลที่ไม่ควรระบุว่าเป็น SecureBERT โดยตรง

| ประเด็น | โมเดลในโปรเจกต์ | SecureBERT ที่เผยแพร่สาธารณะ |
|---|---|---|
| Architecture | ModernBERT | RoBERTa-based |
| Runtime class | `ModernBertForSequenceClassification` | Masked-language model เป็นฐานหลัก |
| งานที่ใช้ | จำแนก command เป็น ATT&CK Technique | ทำความเข้าใจข้อความ Cyber Threat Intelligence |
| Classification head | 196 ATT&CK outputs | ไม่ได้ยืนยันหัวจำแนก 196 classes ของโปรเจกต์นี้ |
| Tokenizer semantics | ModernBERT byte-level BPE | tokenizer ของ SecureBERT คนละชุด |
| Provenance | private project checkpoint | published model/paper |

ชื่อ “SecureBERT” ใน source code จึงเป็น historical/project terminology ไม่ใช่หลักฐาน
ว่า checkpoint นี้สืบสายการเทรนมาจาก published SecureBERT

## 2. บทบาทในระบบ

โมเดลมีบทบาทสามอย่าง:

1. เสนอ ATT&CK Technique candidate จาก command fragment ที่กฎอาจไม่ครอบคลุม
2. สนับสนุนผลของ reviewed rule เมื่อโมเดลและ rule ระบุ Technique เดียวกัน
3. เป็น disagreement signal เมื่อโมเดลที่ผ่าน candidate threshold ระบุ Technique
   ต่างจาก rule ทำให้ระบบระงับผลนั้นไว้เป็น audit-only

โมเดลไม่สามารถ:

- ทำให้ model-only candidate กลายเป็น trusted observation
- แทน label ของ rule ด้วย label ของโมเดล
- เขียน canonical semantic fact โดยตรง
- สั่ง automatic response
- ป้อน model-only result เข้า trusted history หรือ authoritative prediction

## 3. สถาปัตยกรรมที่ยืนยันได้

| รายการ | ค่า |
|---|---:|
| Model class | `transformers.ModernBertForSequenceClassification` |
| Model type | `modernbert` |
| Parameter count | 149,755,588 |
| Transformer layers | 22 |
| Hidden size | 768 |
| Attention heads | 12 |
| Intermediate size | 1,152 |
| Vocabulary size | 50,368 |
| Configured maximum positions | 8,192 |
| Classifier pooling | Mean pooling |
| Classifier activation | GELU |
| Classifier/dropout | 0.0 |
| Output classes | 196 |
| Checkpoint format | safetensors/PyTorch |
| Checkpoint size | 599,036,536 bytes |

หัวจำแนกขนาด `196 × 768` แสดงว่า checkpoint ถูกทำให้เฉพาะกับงานของโปรเจกต์แล้ว
แต่หลักฐานปัจจุบันยังบอกไม่ได้ว่าเริ่มจาก base checkpoint ใด, freeze layer ใด,
ใช้ dataset อะไร หรือใช้ hyperparameters แบบใด

## 4. Input และ preprocessing

Canonical input ของโมเดลคือ raw command fragment ที่ถูก `strip()` แล้ว ไม่ใช่:

- parsed operation
- semantic fact
- คำอธิบายภาษาอังกฤษ
- JSON event ทั้งก้อน
- prompt ที่สร้างขึ้นใหม่

Pipeline แยก compound command ที่ newline, `;`, `&&` และ `||` แต่ไม่แยก pipe
`|` ออกจาก fragment

ข้อควรระวังของ local repo state วันที่ 2026-08-31: test contract กำหนดให้ fragment
ด้านขวาของ `&&`/`||` ถูกระบุเป็น `conditional_unproven` และบังคับเป็น audit-only
เพราะยังพิสูจน์ไม่ได้ว่า execute จริง แต่ `NotebookParityClassifier` ใน local `main`
ยังไม่ได้สร้างค่านี้ครบ ทำให้ test ของ contract ดังกล่าว fail จึงต้องถือว่าเป็น
**known integration gap** และห้ามกล่าวว่าการบังคับนี้ทำงานใน local HEAD จนกว่าจะ
แก้ code/test ให้ตรงกันและยืนยัน active deployed release แยกต่างหาก

Tokenizer ทำงานดังนี้:

1. ทำ Unicode NFC normalization
2. ใช้ case-sensitive byte-level BPE
3. เติม `[CLS]` และ `[SEP]`
4. right-truncate ให้เหลือไม่เกิน 128 tokens
5. right-pad เมื่อทำ batch และสร้าง attention mask

ระบบไม่ทำ lowercase, redaction, argument removal, path/IP/URL replacement,
quote removal หรือ Base64 decoding ดังนั้นสิ่งเหล่านี้มีผลต่อ distribution ของโมเดล

ข้อจำกัดสำคัญคือ tokens หลังตำแหน่ง 128 ถูกทิ้งแบบเงียบ และ classification evidence
ปัจจุบันไม่มี truncation flag

## 5. หลักการ inference

สำหรับ logits `z` จำนวน 196 ค่า:

```text
p_i = exp(z_i) / sum_j(exp(z_j))
selected_index = argmax(p)
selected_ttp = config.id2label[selected_index]
score = p[selected_index]
```

นี่คือ single-label multiclass classification:

- ทุก class แข่งขันกันภายใต้ softmax
- หนึ่ง fragment ให้ model-originated TTP ได้สูงสุดหนึ่งรายการ
- ไม่มี sigmoid, margin, rejection class หรือ multi-label threshold
- ไม่มี temperature scaling สำหรับโมเดลนี้

ฟิลด์ที่เรียกว่า `confidence` คือ top raw softmax score ไม่ใช่ calibrated probability
จึงไม่ควรตีความคะแนน `0.80` ว่ามีโอกาสถูกต้อง 80%

ค่า temperature `0.6990670591704266` เป็นของ next-observed-distinct prediction model
อีกตัวหนึ่ง ห้ามนำมาใช้กับ ModernBERT command classifier นี้โดยไม่มี calibration evidence ใหม่

## 6. การทำงานร่วมกับ Rule engine

Rule engine และโมเดลวิเคราะห์ command เดียวกันอย่างอิสระ ผลโมเดลไม่ได้ถูกส่งเข้า rule
เพื่อให้ rule จำแนกซ้ำ

```text
Cowrie command fragment
  ├─ deterministic parser/rules ──> zero-or-more rule TTPs
  └─ ModernBERT classifier ───────> one TTP + score
                                      │
                         compare + authority decision
                                      │
                        trusted evidence / audit-only
```

Canonical candidate threshold ของโมเดลคือ `0.55` และมีความหมายเพียงว่า candidate
มีสิทธิ์เข้า comparison ไม่ได้ให้ authority แก่โมเดล

| Rule state | Model state | ผลตาม policy |
|---|---|---|
| มี reviewed rule | โมเดลไม่มีผลหรือคะแนนต่ำกว่า 0.55 | rule อาจ trusted ได้ตาม authority decision |
| มี reviewed rule | โมเดลตั้งแต่ 0.55 และ TTP ตรงกัน | corroboration; rule ยังเป็น authority |
| มี reviewed rule | โมเดลตั้งแต่ 0.55 แต่ TTP ต่างกัน | เก็บ rule TTP และ conflicting model TTP เป็น audit-only |
| ไม่มี rule | โมเดลตั้งแต่ 0.55 | model-only candidate เป็น audit-only |
| ไม่มี rule | โมเดลต่ำกว่า 0.55 | low-score candidate/unknown เป็น audit-only |
| โมเดล unavailable/error | ทุกกรณี | rules และ ingest ทำงานต่อ |

ดังนั้นระบบไม่ใช่ weighted ensemble ที่นำ confidence มาบวกหรือเฉลี่ยกัน แต่เป็น hard
authority policy ที่ให้ rule เป็นผู้มีอำนาจ และใช้โมเดลเป็น corroboration/disagreement
signal

เมื่อมองทั้ง production pipeline ตำแหน่งของโมเดลเป็นดังนี้:

```text
Cowrie event
  -> authenticated sensor forwarding / ingest
  -> canonical MongoDB event
  -> SessionWorker + SessionMonitor
  -> command fragment splitter
       |-> structural parser + reviewed rules
       `-> ModernBERT candidate + raw softmax score
  -> authority decision
  -> trusted observation หรือ audit-only candidate
  -> trusted tactic phases / analysis / non-authoritative prediction
```

ชั้นที่เพิ่มขึ้นเหล่านี้ไม่ได้เปลี่ยนสมการ inference ของ ModernBERT แต่ควบคุมว่า output
ของโมเดลมีสิทธิ์ไหลไปส่วนใดต่อได้บ้าง โดย model-only output ไม่สามารถเข้าสู่ trusted
history, canonical findings หรือ response guidance ได้

## 7. ตัวอย่างที่ reproduce แล้ว

| Command | Model result | Rule ที่เกี่ยวข้อง | ความหมาย |
|---|---|---|---|
| `uname -a` | `T1082`, score ≈ 0.6499 | `T1082` | ตรงกัน; rule remains authority |
| `whoami` | `T1056`, score ≈ 0.5154 | `T1033` | โมเดลต่ำกว่า 0.55; rule ยังอาจ trusted |
| `wget ... /tmp` | `T1548`, score ≈ 0.1300 | `T1105` | โมเดลต่ำกว่า threshold |
| `cat /etc/passwd` | `T1087`, score ≈ 0.3862 | `T1003` | โมเดลต่ำกว่า threshold |

ผลทดสอบ sensitivity แสดงว่า case, quoting, separator, payload length และตำแหน่ง
ข้อความสำคัญทำให้ distribution เปลี่ยนได้ จึงยังกล่าวเรื่อง robustness ไม่ได้

## 8. Failure และ production behavior

- ถ้า import, tokenizer หรือ checkpoint โหลดไม่ได้ wrapper จะคืน unavailable/`None`
  และ rules/ingest ทำงานต่อ
- Model exception ถูกกักเป็น audit-only status
- Session worker โหลดโมเดลแบบ eager หนึ่งครั้งต่อ worker
- Analysis path อาจสร้างโมเดลใหม่ต่อ analysis job
- Inference เป็น synchronous และไม่มี forward timeout
- Local CPU profile ที่บันทึกไว้คือประมาณ 29.6–36.9 ms สำหรับคำสั่งสั้น และ
  142–145 ms ที่ความยาว 128 tokens; ไม่ใช่ SLA
- Peak process RSS ที่วัดได้ประมาณ 845,584 KiB

Active-release contract มี classifier-environment manifest สำหรับผูก expected source/asset
identity และ fail closed เมื่อ environment binding ไม่ถูกต้อง อย่างไรก็ตาม ordinary
`SecureBERTClassifier` loader เองยังไม่ได้ re-hash bytes ของ checkpoint, tokenizer,
config และ label mapping ทุกครั้งก่อน `from_pretrained()` จึงยังต้องแยกความหมายระหว่าง
"manifest ผูก expected identity" กับ "loader ตรวจ live asset bytes ณ เวลา load"

## 9. สิ่งที่กล่าวอ้างได้และไม่ได้

กล่าวอ้างได้:

- เป็น private ModernBERT-based ATT&CK command classifier
- output เป็นหนึ่ง top-ranked Technique ต่อ fragment
- inference reproduce และ deterministic บน CPU/environment ที่ทดสอบสำหรับ bytes เดิม
- model-only output ไม่มี authority

ยังกล่าวอ้างไม่ได้:

- เป็น published SecureBERT หรือสืบสายการเทรนจากโมเดลดังกล่าว
- เพิ่ม detection accuracy
- generalize ไปยังคำสั่งที่ไม่เคยเห็น
- confidence ผ่าน calibration แล้ว
- threshold 0.55 เป็นค่าที่ optimal
- training สามารถ reproduce ได้ครบ
- robust ต่อ adversarial input หรือ tail ที่ถูก truncate

## 10. กติกาการอัปเดต LIVE STATE

เมื่อมีการเปลี่ยน checkpoint, tokenizer, label order, max length, threshold, preprocessing
หรือ authority policy ต้อง:

1. อัปเดต `ปรับปรุงล่าสุด` และ `หลักฐานล่าสุดที่ใช้ยืนยัน`
2. บันทึก asset/source hashes ที่เปลี่ยน
3. rerun identity verification, bounded inference และ authority tests
4. อัปเดตตัวอย่าง output และข้อจำกัด
5. ห้ามนำ metric หรือ calibration ของโมเดลอื่นมาใช้ข้าม identity

## 11. สถานะ integration ใน repo หลัก ณ 2026-08-31

- แกน production ปัจจุบันอยู่ใน `honeypot-analysis/`; Go agents เป็นอีก
  target/legacy/external pipeline ไม่ใช่ตำแหน่ง inference หลักของ ModernBERT
- เอกสาร production ปัจจุบันยืนยันว่า SecureBERT เป็น candidate/corroboration เท่านั้น
  และ model-only หรือ disagreement เป็น audit-only
- Local branch `main` ahead `origin/main` 3 commits และ working tree สะอาดตอนตรวจ
- `pytest --collect-only` พบ 1,806 tests แต่มี 13 collection errors จาก API/constants
  ที่ test กับ implementation ใน local HEAD ไม่ตรงกัน
- authority test ของ conditional RHS มีอย่างน้อยหนึ่งกรณี fail ตาม integration gap ใน
  Section 4
- สถานะ local HEAD ข้างต้นห้ามใช้สรุปแทนสถานะ content-addressed release ที่ deploy อยู่;
  ต้องตรวจ receipt/runtime ของ release นั้นแยกต่างหาก

## เอกสารหลักฐานในโฟลเดอร์นี้

- [Final review](securebert_review_final_report.v1.md)
- [Architecture](securebert_architecture.v1.json)
- [Inference pipeline](securebert_inference_pipeline.v1.md)
- [Output semantics](securebert_output_semantics.v1.md)
- [Authority matrix](securebert_rule_model_authority_matrix.v1.json)
- [Tokenizer review](securebert_tokenizer_review.v1.json)
- [Training provenance](securebert_training_provenance.v1.json)
- [Evaluation review](securebert_evaluation_metrics_review.v1.json)
- [Fail-closed review](securebert_fail_closed_review.v1.json)

## หลักฐานจาก repo หลัก

- `honeypot-analysis/CURRENT_SYSTEM_FULL_TECHNICAL_DOCUMENTATION.md`
- `honeypot-analysis/production/classification/classification_pipeline.py`
- `honeypot-analysis/production/classification/securebert_classifier.py`
- `honeypot-analysis/production/classification/authority.py`
- `honeypot-analysis/production/classification/trust.py`
- `honeypot-analysis/tests/test_phase1_command_authority_v2.py`

## External references

- SecureBERT paper: https://arxiv.org/abs/2204.02685
- Published SecureBERT model: https://huggingface.co/ehsanaghaei/SecureBERT
- ModernBERT paper: https://arxiv.org/abs/2412.13663
- Transformers ModernBERT documentation:
  https://huggingface.co/docs/transformers/model_doc/modernbert
