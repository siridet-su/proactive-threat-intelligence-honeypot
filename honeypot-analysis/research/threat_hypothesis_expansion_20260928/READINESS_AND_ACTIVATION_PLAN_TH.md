# ขยาย Threat Hypothesis และ Response Guidance: ผลตรวจ source และแผนเปิดใช้

สถานะ: **RESEARCH_ONLY / ยังไม่เปิดใน production** (28 ก.ย. 2026)

เอกสารนี้แยกสามเรื่องให้ชัด: สิ่งที่ระบบแสดงอยู่แล้ว, candidate ที่ทดสอบกับ parser/selector จริงแบบ offline, และแนวคิดที่ต้องเพิ่มหลักฐานหรือ policy ก่อนจึงจะใช้ได้ ผล candidate ไม่ใช่การประเมินความแม่นยำกับการโจมตีจริง

## เส้นทางข้อมูลและข้อจำกัดปัจจุบัน

Cowrie command/input/outcome และ direct transfer event ถูกแปลงเป็น typed facts ที่มี operation, path/URL entity, outcome และเวลาของ event ตัวเลือก chain เดิมยอมรับเฉพาะความสัมพันธ์ `same_path_transition` ที่ผูก resolved path และเรียงลำดับได้ ตัวสร้าง `session_assessment.v4/v5` ส่ง incomplete chain เป็น hypothesis set ซึ่งมีทางเลือกอย่างน้อยสองทาง ผล Model1, Model2, enrichment หรือ AI ไม่เพิ่มสิทธิ์ให้สร้าง canonical finding หรือสั่ง response

Policy ปัจจุบันเปิด typed connected chain `transfer_attempt → permission_modify → execution_attempt` เพียงชุดเดียว กรณีมีสองขั้นแรกแต่ไม่พบ execution จะได้ hypothesis; กรณีครบสามขั้นเป็น bounded finding การพบ `file_download` พร้อม hash เป็น direct transfer finding แยกต่างหาก

`response_guidance.v4` อ่าน canonical graph และ policy ที่ผูก exact file/document hashes ใน reviewed registry; เลือก actions จาก observed facts และมี `requires_manual_approval=true`, `safe_to_auto_execute=false`, `execution_integration=not_implemented` ทุก action Policy เดิมมี playbook สำหรับ observed command, credential read, direct transfer และ execution attempt การเพิ่มข้อความใน policy โดยไม่ผ่าน review/registry จะ fail closed ตามที่ออกแบบไว้

## Candidate ที่ replay ได้แล้ว

โค้ดทดลองอยู่ใน `candidate.py`; ฟังก์ชัน `evaluate_candidate(fact_set)` รับ validated typed fact set และคืนเฉพาะ ID/refs/ข้อความที่มีขอบเขต ไม่ส่ง raw command, path, URL หรือ credential ออกมา และไม่มี production write authority

| Candidate | หลักฐานที่ต้องครบ | ผลเมื่อครบ | หลักฐานที่ยังขาด / สิ่งที่หักล้างได้ |
| --- | --- | --- | --- |
| เตรียมไฟล์แต่ยังไม่รัน | `file_write → permission_modify` บน resolved path เดียวกัน, timestamp รองรับ, outcome ของทั้งสองคำสั่ง reported-success | สองสมมติฐาน: เตรียมไฟล์เพื่อใช้ภายหลัง หรือเป็นการจัดการไฟล์ทั่วไป/หยุดไว้ | ยังไม่พบ execution บน path เดียวกัน; failed write หรือ path ต่างกันทำให้ candidate หาย |
| เรียกใช้หลังพยายาม transfer โดยไม่ยืนยันการรับไฟล์ | `transfer_attempt → execution_attempt` บน resolved path เดียวกัน, timestamp รองรับ, outcome ที่ Cowrie รายงานว่า success ทั้งคู่ และไม่มี direct transfer event ใน session | สองสมมติฐาน: พยายามใช้ไฟล์ที่ขอจาก remote หรือ execute อาจอ้างถึงไฟล์เดิม | ไม่มีหลักฐาน bytes/hash ของ transfer; direct transfer event หรือ failed fetch เปลี่ยนสถานะหลักฐาน |
| ตรวจการเปลี่ยนไฟล์ | `file_write` หรือ `permission_modify` ที่ reported-success พร้อม resolved/linkable path | guidance candidate ให้นักวิเคราะห์ตรวจ file audit และสถานะไฟล์จริง | ไม่อนุมานว่าระบบจริงถูกแก้; ไม่เสนอถ้า path ไม่ resolve หรือ command failed |
| ตรวจลำดับเรียกใช้แล้วลบ | `execution_attempt → file_delete` บน resolved path เดียวกัน พร้อม timestamp และ outcome ที่เข้าเกณฑ์ | guidance candidate ให้ตรวจ process/file audit ตาม path และช่วงเวลา | ไม่อนุมานเจตนาลบร่องรอย; สองเหตุการณ์นี้เป็น observations ไม่ใช่ incomplete hypothesis |

Candidate จะไม่สร้าง hypothesis ซ้ำบน entity ที่ policy เดิมเลือก chain ไว้แล้ว และจะงด transfer hypothesis หากมี direct transfer event ใด ๆ ใน session เพราะ contract นี้ยังไม่สามารถพิสูจน์ hash-to-path binding ของ event นั้นในทุกกรณี การงดแบบนี้อาจพลาด candidate บางกรณีที่ไม่เกี่ยวกัน แต่หลีกเลี่ยงคำว่า “unconfirmed transfer” ทั้งที่มี event ยืนยันอยู่

## กรณีที่ต้องทำก่อนเปิดเพิ่ม

| แนวคิด | สิ่งที่ source มีแล้ว | ตัวบล็อกที่ต้องปิด |
| --- | --- | --- |
| transfer → ลบไฟล์ | transfer attempt, deletion และ path entity | ต้องแยก attempt จาก direct transfer event และพิสูจน์ hash/path binding ก่อนสรุปว่าเป็นไฟล์เดียวกัน |
| file move → execute ชื่อใหม่ | `file_move`, source/destination path, execution | ตัวเลือก chain ปัจจุบันใช้ same-path; ต้องเพิ่ม identity transition จาก source ไป destination พร้อม negative tests |
| decode → write → execute | `decode_transform`, file write, execution | transformation family ยังไม่ active และยังไม่มี data-flow ที่พิสูจน์ว่า output ถูกเขียนเป็นไฟล์ที่รัน |
| remote content → shell ผ่าน pipe | parser มี operation และ `piped_to` | ต้องประเมิน pipe semantics, outcomes, payload direction และไม่ตีความข้อความที่เพียงถูกพิมพ์ว่า execute สำเร็จ |
| archive → outbound transfer | `archive_create` และ transfer attempt | collection family ยังไม่ active; ไม่มี outbound upload/content binding ที่ผ่านเกณฑ์ |
| credential read → outbound transfer | credential-path read และ transfer attempt | ลำดับเวลา/การอยู่ใน session เดียวกันไม่พิสูจน์ data flow ต้องมี outbound direction, input-to-output binding และ benign controls |
| scheduled task/service/account persistence | schedule/service/account operations | family บางส่วนยังไม่ active และยังไม่ผูก target executable, service/account identity หรือ auth event ข้ามคำสั่งได้ครบ |
| login failed → success | Cowrie auth events | ต้องกำหนด grouping, window, account binding, hard negatives และห้ามถือว่า Cowrie login คือ real credential compromise |
| HTTP probing / injection | HTTP request chronology และ injection hints | ต้องสร้าง HTTP-specific fact/identity contract; cookie เป็นความต่อเนื่องของ browser เท่านั้น และ 2xx ไม่พิสูจน์ exploit |

## การเพิ่ม Response Guidance หลัง review

Action ใหม่ควรอ้าง fact refs และ evidence refs จาก canonical graph โดยตรง; แบบอาศัย chain ให้ตรวจ relationship refs และ entity identity ด้วย รายการที่ควรนำไป review ก่อนคือ file-change review และ file-lifecycle review ข้างบน ปัจจุบัน `_rule_match` ของ `response_guidance.v4` เลือกได้จาก fact รายตัว ยังไม่มี chain predicate หรือการรวมหลาย file-change facts บน path เดียวกัน จึงต้องเพิ่ม matcher/validator และตรวจว่า replay กับ immutable report เดิมยังผ่านก่อนเปิด action สองแบบนี้ใน runtime ส่วน remote-content, archive/outbound, scheduled-task/service, HTTP application และ account review ต้องรอ fact/relationship contract ของแต่ละ family ก่อน

ทุก action ต้องบอกเหตุที่เสนอและ telemetry ที่ให้คนตรวจต่อ พร้อม `requires_manual_approval=true`, `safe_to_auto_execute=false` และไม่มี execution integration คำกล่าวเรื่อง persistence, compromise, exfiltration หรือการลบร่องรอยไม่ใช่ผลที่ยืนยันจาก Cowrie command อย่างเดียว

## ขั้นตอน activation ที่ยังต้องทำ

1. ผู้ดูแล policy ตรวจข้อความ candidate, hard negatives, source provenance และ scope แล้วตัดสินว่าจะรับกฎใดเข้าชุด trusted policy โดยลงชื่อ/รุ่นใหม่อย่างตรงไปตรงมา ห้ามยกสถานะ reviewed จาก policy เดิมมาให้ข้อความใหม่โดยอัตโนมัติ
2. เพิ่มกฎ file-write→chmod→execution ที่รับแล้วใน `threat_hypothesis_behavior.trusted.json` และขยายตัวเลือก chain สำหรับกรณี transfer→execution ที่ครบสองคำสั่งแต่ขาด direct-transfer confirmation อย่าง explicit; อย่าใส่ operation ที่ไม่เกี่ยวข้องเป็นขั้นที่สามเพียงเพื่อบังคับให้ status กลายเป็น incomplete
3. ขยาย response-guidance matcher/validator ให้รองรับ observed chain และการรวม facts บน resolved path เดียวกัน แล้วจึงเพิ่ม playbooks ใน `response_guidance_policy.v3.json`; อัปเดต exact hash registry ของ `response_guidance.v4` โดยเก็บ hash เก่าสำหรับ immutable reports; ตรวจ source-artifact/reference bindings ตาม validator
4. ทดสอบ replay ทั้ง success, wrong path, reverse order, failed/unknown outcome, direct transfer event, duplicate chain, truncation/stale evidence และกรณีเดียวกันที่มี Model2/AI/ETI context เพื่อพิสูจน์ว่า context ไม่เปลี่ยน authority
5. ตรวจ projection ไป `monitor_web`, Dashboard, AI advisory และ PDF ด้วย session ที่ผูก evidence refs ได้จริง; แสดง “พบอะไร / ทางเลือก / สิ่งที่ยังไม่รู้ / ตรวจต่ออย่างไร” และไม่บังคับ render หาก record ไม่ผ่าน validator
6. ตรวจ runtime identity และ host rollout แยกจากการทดสอบ offline; หลังผ่านจึงพิจารณา staging และ live smoke ตาม change procedure เดิม

## หลักฐานการทดสอบรอบนี้

`pytest tests/test_research_hypothesis_expansion_20260928.py -q` ผ่าน 8/8 และเมื่อรวม behavioral-remediation กับ response-guidance-v3 tests ผ่าน 19/19 ครอบคลุม scenario ที่สร้าง candidate, full chain ที่ต้องไม่ซ้ำ, direct transfer event, wrong path, reverse order, failed outcome, guidance manual-only และการไม่ส่ง raw command/path ออกมา ผลเป็น **mechanics/contract replay** จากข้อมูลสังเคราะห์ที่กำหนดล่วงหน้า ไม่ใช่ precision, recall หรือ production accuracy

การลอง broad regression ใน checkout นี้พบ import error ของ `CONTROLLED_SYNTHETIC_PROVENANCE_MARKER` ระหว่างเก็บชุด v6 graph-guidance และ test v5-to-AI projection เดิมหนึ่งรายการไม่ผ่าน report validation ปัญหาทั้งสองอยู่นอก research package นี้ แต่ต้องตรวจให้จบก่อนอ้างว่าการเชื่อม backend/AI/PDF พร้อมใช้งาน

ไม่แก้ policy เดิม, API contract, Dashboard, PDF, model, threshold หรือ host runtime; ไม่สร้าง live session, provider request หรือ Mongo write ในงานวิจัยนี้

## Addendum 28 ก.ย. 2026 — implementation candidate หลังผู้ใช้อนุมัติข้อความ

หลังบันทึกผล research-only ข้างต้น มีการเตรียม source/policy รุ่นใหม่ใน isolated checkout แยกต่างหาก ข้อความ H1/H2/G1/G2 ได้รับการอนุมัติจากเจ้าของโครงการแล้ว แต่ **ยังไม่ deploy และยังไม่ active บน GCP**

- H1/H2 ใช้ hypothesis-only gate; H2 ที่ chain ครบยังไม่กลายเป็น trusted finding และงดเมื่อมี direct transfer event ใน session; H1 งดเมื่อมี execution บน path เดียวกันหรือมี baseline chain ที่ครอบคลุม
- G1/G2 มี matcher ทั้งในเส้นทางจริง `session_assessment.v4 → response_guidance.v3` และเส้นทาง `response_guidance.v4`; v3 ใช้ typed facts ที่ผ่าน validation ส่วน v4 ใช้ canonical graph; ทั้งสองให้ผล rule ID ตรงกันใน replay
- G1 รวม file-write/permission-change ที่ Cowrie รายงานสำเร็จบน resolved path เดียวกันเป็นหนึ่ง manual action; G2 ต้องมี execution→deletion บน path เดียวกัน ลำดับเวลาและความสัมพันธ์ที่รองรับ
- Regression สำหรับกรณี positive/negative ใหม่ผ่าน 6/6; ชุด policy/response/research ผ่าน 28/28 และชุด assessment/API/AI-presentation แบบเจาะจงผ่าน 54 รายการ (ข้าม 1) แต่ broad v5/AI ยังมี import errors สองจุดและ v5→AI validation failure ตามที่ระบุไว้ก่อนหน้า จึงยังไม่ผ่าน production release gate
- ต้องตรวจ full-suite, immutable manifest/provenance และ authenticated UI/PDF replay ก่อนปล่อยขึ้น GCP ห้ามกล่าวว่า feature ใหม่ใช้งานจริงแล้วจากผลทดสอบ offline
