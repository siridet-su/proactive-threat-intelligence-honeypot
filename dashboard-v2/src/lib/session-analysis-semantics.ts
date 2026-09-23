export type SessionAnalysisRecord = Record<string, unknown>;
export type SessionLifecycleStatus = "Active" | "Closed" | "Unknown";

/**
 * แปลงข้อมูลที่ไม่ทราบประเภทให้กลายเป็น Object เสมอ เพื่อป้องกัน Error 
 * @param {unknown} value - ค่าที่ต้องการแปลง
 * @returns {SessionAnalysisRecord} - Object ที่แปลงแล้ว (หากไม่ใช่ Object จะคืนค่า Object ว่าง)
 */
function record(value: unknown): SessionAnalysisRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as SessionAnalysisRecord
    : {};
}

/**
 * ตรวจสอบว่าค่านั้นๆ มีความหมาย (ไม่ว่างเปล่า ไม่เป็น null/undefined)
 * @param {unknown} value - ค่าที่ต้องการตรวจสอบ
 * @returns {boolean} - true หากค่านั้นสามารถนำไปใช้ต่อได้
 */
function meaningful(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (typeof value === "string") return value.trim().length > 0;
  return true;
}

/**
 * แปลงข้อมูลเวลาให้กลายเป็นตัวเลข Milliseconds เพื่อใช้ในการคำนวณ
 * @param {unknown} value - ข้อมูลเวลา (ตัวเลข หรือ สตริงวันที่)
 * @returns {number | null} - ตัวเลขเวลาในหน่วยมิลลิวินาที หรือ null หากแปลงไม่ได้
 */
function timestampMillis(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "string" || !value.trim()) return null;
  const numeric = Number(value);
  if (Number.isFinite(numeric)) return numeric;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * แปลงข้อมูล Sequence ให้เป็นตัวเลข
 * @param {unknown} value - ค่า Sequence (ตัวเลข หรือ สตริง)
 * @returns {number | null} - ตัวเลข Sequence หรือ null หากแปลงไม่ได้
 */
function sequenceNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "string" || !value.trim()) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * ดึงข้อมูลเวลาหลักที่เชื่อถือได้มากที่สุดจาก Record ของเหตุการณ์
 * @param {SessionAnalysisRecord} value - ข้อมูลเหตุการณ์
 * @returns {unknown} - ค่าเวลาที่พบ (ตามลำดับความสำคัญของฟิลด์)
 */
export function authoritativeEventTimestamp(value: SessionAnalysisRecord): unknown {
  return value.timestamp ?? value.event_timestamp ?? value.received_at ?? value.updated_at;
}

/**
 * ดึงลำดับเหตุการณ์ (Sequence) ที่เชื่อถือได้มากที่สุดจาก Record
 * @param {SessionAnalysisRecord} value - ข้อมูลเหตุการณ์
 * @returns {number | null} - ตัวเลข Sequence ที่พบ หรือ null
 */
function authoritativeEventSequence(value: SessionAnalysisRecord): number | null {
  const durableOrder = record(value.durable_evidence_order);
  for (const candidate of [
    value.sequence,
    value.sequence_index,
    value.event_sequence,
    durableOrder.sequence,
    durableOrder.sequence_index,
  ]) {
    const parsed = sequenceNumber(candidate);
    if (parsed !== null) return parsed;
  }
  return null;
}

/**
 * จัดเรียงข้อมูลเหตุการณ์ตามลำดับเวลา (Chronological order) 
 * โดยใช้ Timestamp เป็นหลัก หากเท่ากันจะใช้ Sequence และหากเท่ากันอีกจะใช้ลำดับเดิมใน Array
 * 
 * @param {unknown[]} items - Array ของเหตุการณ์ที่ยังไม่จัดเรียง
 * @returns {SessionAnalysisRecord[]} - Array ของเหตุการณ์ที่จัดเรียงลำดับเรียบร้อยแล้ว
 */
export function chronologicalRecords(items: unknown[]): SessionAnalysisRecord[] {
  return items
    .map((value, index) => {
      const item = record(value);
      return {
        item,
        index,
        timestamp: timestampMillis(authoritativeEventTimestamp(item)),
        sequence: authoritativeEventSequence(item),
      };
    })
    .sort((left, right) => {
      if (left.timestamp !== null && right.timestamp !== null && left.timestamp !== right.timestamp) {
        return left.timestamp - right.timestamp;
      }
      if (left.timestamp === null && right.timestamp !== null) return 1;
      if (left.timestamp !== null && right.timestamp === null) return -1;
      if (left.sequence !== null && right.sequence !== null && left.sequence !== right.sequence) {
        return left.sequence - right.sequence;
      }
      if (left.sequence === null && right.sequence !== null) return 1;
      if (left.sequence !== null && right.sequence === null) return -1;
      return left.index - right.index;
    })
    .map(({ item }) => item);
}

/**
 * ทำความสะอาดสตริงสถานะให้อยู่ในรูปแบบตัวพิมพ์เล็กทั้งหมด
 * @param {unknown} value - ค่าสถานะดิบ
 * @returns {string} - สถานะที่แปลงเป็นตัวพิมพ์เล็ก (หรือค่าว่างหากไม่ใช่สตริง)
 */
function statusText(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

/**
 * ประเมินสถานะของ Session (Active, Closed, หรือ Unknown) 
 * จากร่องรอยข้อมูลที่ถูกบันทึกไว้ใน Record ต่างๆ ของ Session
 * 
 * @param {SessionAnalysisRecord} detail - ข้อมูลรายละเอียดของ Session
 * @returns {SessionLifecycleStatus} - สถานะของ Session
 */
export function sessionLifecycleStatus(detail: SessionAnalysisRecord): SessionLifecycleStatus {
  const sources = [
    record(detail.session),
    record(detail.overview),
    record(detail.session_payload),
    detail,
  ];
  let sawActive = false;

  for (const source of sources) {
    if (source.is_ended === true || source.ended === true) return "Closed";
    if (meaningful(source.end_time) || meaningful(source.ended_at) || meaningful(source.closed_at)) {
      return "Closed";
    }
    const statuses = [source.status, source.session_status, source.lifecycle_status]
      .map(statusText)
      .filter(Boolean);

    if (statuses.some((value) => ["closed", "ended", "complete", "completed", "terminated", "disconnected"].includes(value))) {
      return "Closed";
    }

    if (source.is_ended === false || source.ended === false || statuses.some((value) => ["active", "open", "connected", "running"].includes(value))) {
      sawActive = true;
    }
  }
  return sawActive ? "Active" : "Unknown";
}