# Dataset Split Policy v1

> สถานะ: `IMPLEMENTED TOOLING / INSUFFICIENT ELIGIBLE DATA`
> ใช้กับ: Cowrie Hardware Fusion controlled datasets

## หลักการ

หน่วย split คือ `run_id` ทั้ง run ไม่ใช่ telemetry rows, commands หรือ overlapping
windows ข้อมูลที่สืบทอดจาก run เดียวกันต้องอยู่ split เดียวกันเสมอ

## Dataset partitions

```text
development_train  70%
calibration         15%
final_test          15%
```

Pilot dataset ใช้ตรวจ collector/schema เท่านั้นและมี `pilot_only=true`; ห้ามนำ pilot
runs ไปเพิ่มจำนวน final test ภายหลัง

หากจำนวน independent groups ยังน้อย ให้ใช้ GroupKFold ภายใน development partition
และยังไม่สร้าง claim จาก final test จน support ต่อ label เพียงพอ

Implementation ปัจจุบันใช้ connected components: ถ้า runs แชร์ค่าบน leakage axis ใด
axis หนึ่ง runs เหล่านั้นต้องอยู่ component/partition เดียวกัน ค่า `no-command` ไม่สร้าง
edge เฉพาะ command-template axis และ `none`/zero hash ไม่สร้าง edge เฉพาะ workload
identity axis เพราะไม่ได้แทน identity จริง; ค่าเดียวกันบน batch/environment axis ยัง
สร้าง edge ตามปกติ ผู้ใช้เลือก axes ได้แต่ assignment receipt ต้องบันทึก axes และ seed
เสมอ

## Group boundaries

Split generator ต้องป้องกัน group ต่อไปนี้ข้าม partition:

- `run_id`
- scenario variant
- workload implementation family/hash
- command template family
- payload/tool family
- experiment collection day/batch
- backend image/environment signature เมื่อใช้เป็น holdout axis

อย่างน้อยหนึ่ง scenario/workload/command variant ต่อ target family ต้องถูก hold out จาก
development เพื่อทดสอบ generalization หากจำนวนข้อมูลรองรับ

## Derived data inheritance

- ทุก 5/10/30/60-second window inherit partition จาก parent run
- command fragments จาก session/run เดียวกัน inherit partition เดียวกัน
- telemetry จากหลาย scopes ของ run เดียวกันอยู่ partition เดียวกัน
- augmented/normalized/cached representation inherit source partition
- duplicate/near-duplicate run ต้องถูก group ก่อน split

## Prohibited model features

ห้ามใช้ identifiers หรือ acquisition artifacts ต่อไปนี้เป็น model features:

- `run_id`, `experiment_id`, `scenario_id`
- `sensor_id`, `subject_id`, backend/container name
- exact workload implementation name/hash
- command template ID
- collection day, absolute timestamp หรือ split name
- explicit ground-truth/evidence receipt fields
- phase label ถ้า deployment runtime ไม่สามารถสร้าง phase ด้วยหลักฐานเดียวกัน

ค่าดังกล่าวเก็บเพื่อ audit/grouping ได้ แต่ต้องถูกตัดจาก feature matrix

## Preprocessing isolation

Fit เฉพาะ development train:

- scaler/normalizer
- imputation values
- feature selection/PCA
- class weights/resampling
- XGBoost hyperparameters
- TCN architecture/early stopping
- decision thresholds

Calibration fit เฉพาะ calibration partition หลัง freeze model selection

Final test ห้ามใช้เพื่อเลือก feature, architecture, epoch, threshold หรือ calibration

## Fusion leakage control

ถ้า hardware branch ถูก train ด้วย dataset นี้ Fusion ต้องรับ hardware predictions จาก
out-of-fold base models สำหรับ development rows ไม่ใช่ in-sample predictions

ModernBERT ที่ freeze จาก checkpoint เดิมอาจสร้าง features ได้โดยไม่ fine-tune บน
dataset นี้ หาก fine-tune เมื่อใด ต้องเปลี่ยน experiment identity และสร้าง out-of-fold
text predictions เช่นเดียวกัน

## Final test protocol

1. Freeze dataset manifest และ group assignment
2. Freeze feature schema, model config และ seeds
3. Train/select บน development partition
4. Fit calibration/threshold บน calibration partition
5. เปิด final test หนึ่งครั้งตาม protocol
6. บันทึก code/config/model/data hashes และทุก metric ใน immutable receipt
7. การเปิด test ซ้ำหรือปรับหลังเห็นผลต้องสร้าง evaluation generation ใหม่และลดระดับ claim

## Required leakage tests

- ไม่มี `run_id` อยู่มากกว่าหนึ่ง partition
- ไม่มี raw sample/window hash ซ้ำข้าม partition
- ไม่มี command template/workload hash ที่กำหนด holdout ปรากฏใน train
- feature columns ไม่มี prohibited identifiers
- scaler/imputer/selector ไม่มี fit receipt จาก validation/test
- fusion development rows ใช้ out-of-fold base predictions
- controlled/synthetic runs ไม่ถูกนับเป็น `production_live`

## Stage A gate result

source index จาก neutral-idle pilot 3 runs ผ่านการตรวจ raw 270 records และมี hash
`63a10edf5e6f9b4ed4b1254a390328d7ad7f99debe5a1861f38c5de68e3599b9` แต่ทั้งสาม
runs เป็น `pilot_only=true` จึงมี eligible run เท่ากับ 0 และ split generator ปฏิเสธ
การสร้าง train/calibration/test assignment ตามที่ออกแบบไว้
