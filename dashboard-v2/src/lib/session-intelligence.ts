export type IntelligenceRecord = Record<string, unknown>;
export type EnsembleEvidenceState =
  | "AGREE"
  | "DISAGREE"
  | "MODEL1_ONLY"
  | "MODEL2_ONLY"
  | "MODEL2_UNAVAILABLE"
  | "MODEL1_NOT_APPLICABLE";

export const SAFE_PROVIDER_CONTEXT_KEYS = new Set([
  "malicious", "suspicious", "harmless", "undetected", "timeout",
  "detection_numerator", "detection_denominator", "meaningful_name",
  "type", "reputation_label", "pulses", "asn", "organization", "isp",
  "country", "ports", "services", "cpe", "vulnerabilities", "tags",
  "hostnames", "last_update", "abuse_confidence_score", "total_reports",
  "categories", "usage_type", "country_code", "last_reported_at",
]);

/**
 * แปลงค่าที่รับมาให้มั่นใจว่าเป็น Object เสมอ
 * @param {unknown} value - ค่าที่ต้องการแปลง
 * @returns {IntelligenceRecord} - Object ที่แปลงแล้ว (หากรับค่าที่ไม่ใช่ Object จะได้ Object ว่าง)
 */
export function intelligenceRecord(value: unknown): IntelligenceRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as IntelligenceRecord
    : {};
}

/**
 * ตรวจสอบว่าข้อความถูกเซ็นเซอร์ (Redacted) หรือไม่
 * @param {string} value - ข้อความที่ต้องการตรวจสอบ
 * @returns {boolean} - true หากข้อความเป็น "[REDACTED]"
 */
function isRedactionMarker(value: string): boolean {
  return value.trim().toUpperCase() === "[REDACTED]";
}

/**
 * ดึงข้อความคำสั่ง (Command Text) ที่ผู้โจมตีพิมพ์ออกมา 
 * โดยจะหาจากฟิลด์ต่างๆ และกรองข้อมูลที่ถูกเซ็นเซอร์ออก
 * 
 * @param {unknown} value - ข้อมูลเหตุการณ์ที่มีฟิลด์คำสั่ง
 * @returns {string | null} - ข้อความคำสั่ง หรือ null หากไม่มีหรือถูกเซ็นเซอร์
 */
export function analystCommandText(value: unknown): string | null {
  if (typeof value === "string") {
    return value.trim() && !isRedactionMarker(value) ? value : null;
  }
  const item = intelligenceRecord(value);
  for (const key of ["command_text", "input", "command", "text", "source_command"]) {
    const candidate = item[key];
    if (typeof candidate === "string" && candidate.trim() && !isRedactionMarker(candidate)) {
      return candidate;
    }
  }
  return null;
}

/**
 * ดึงชื่อผู้ใช้งาน (Username) ที่ผู้โจมตีใช้ล็อกอิน 
 * จะคืนค่ากลับมาก็ต่อเมื่อระบบตั้งค่าให้แสดงผลได้ (AVAILABLE) เท่านั้น
 * 
 * @param {unknown} value - ข้อมูลเหตุการณ์การล็อกอิน
 * @returns {string | null} - ชื่อผู้ใช้งาน หรือ null หากไม่ได้รับอนุญาตหรือถูกเซ็นเซอร์
 */
export function analystAttackerUsername(value: unknown): string | null {
  const item = intelligenceRecord(value);
  if (String(item.username_visibility || "").toUpperCase() !== "AVAILABLE") return null;

  const candidate = item.attacker_username;
  return typeof candidate === "string" && candidate.trim() && !isRedactionMarker(candidate)
    ? candidate
    : null;
}

/**
 * แปลงค่าข้อมูลจาก Provider ให้เป็นข้อความที่พร้อมแสดงผล
 * 
 * @param {unknown} value - ข้อมูลที่ได้รับจากภายนอก
 * @returns {string} - ข้อมูลในรูปแบบข้อความ (หากเป็น Array จะต่อด้วยลูกน้ำ สูงสุด 12 รายการ)
 */
function providerValue(value: unknown): string {
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value)) {
    return value
      .filter((item) => typeof item === "string" || typeof item === "number" || typeof item === "boolean")
      .slice(0, 12)
      .map(String)
      .join(", ");
  }
  return "";
}

/**
 * สกัดข้อมูลเฉพาะฟิลด์ที่ปลอดภัย (Safe Context Keys) จาก Provider
 * 
 * @param {unknown} value - ข้อมูลจาก Provider
 * @returns {Array<readonly [string, string]>} - Array ของ [Key, Value] สำหรับนำไปแสดงเป็นตาราง
 */
export function selectedProviderFields(value: unknown): Array<readonly [string, string]> {
  return Object.entries(intelligenceRecord(value))
    .filter(([key]) => SAFE_PROVIDER_CONTEXT_KEYS.has(key))
    .map(([key, item]) => [key, providerValue(item)] as const)
    .filter(([, rendered]) => rendered.length > 0);
}

/**
 * ประเมินสถานะการทำงานร่วมกันของโมเดล (Ensemble Evidence State) 
 * เพื่อเปรียบเทียบผลลัพธ์ระหว่าง Model 1 และ Model 2 (Shadow Model)
 * 
 * @param {unknown} value - ข้อมูลการประเมินภัยคุกคามที่มีผลลัพธ์จากหลายโมเดล
 * @returns {EnsembleEvidenceState} - สถานะข้อสรุปจากหลายโมเดล
 */
export function ensembleEvidenceState(value: unknown): EnsembleEvidenceState {
  const item = intelligenceRecord(value);
  const model1 = intelligenceRecord(item.s1_advisory);
  const model2 = intelligenceRecord(item.shadow_model);

  const model1Technique = String(model1.predicted_technique || "").trim();
  const model2Technique = String(model2.technique_id || "").trim();
  const model1Status = String(model1.status || "").toLowerCase();
  const model2Status = String(model2.status || "").toLowerCase();

  const model1NotApplicable = ["not_applicable", "skipped", "short_input_skipped"].includes(model1Status);
  const model2Unavailable = ["unavailable", "error", "missing"].includes(model2Status);

  if (model1NotApplicable) return "MODEL1_NOT_APPLICABLE";

  if (model1Technique && model2Technique) {
    return model1Technique === model2Technique ? "AGREE" : "DISAGREE";
  }

  if (model1Technique) return model2Unavailable ? "MODEL2_UNAVAILABLE" : "MODEL1_ONLY";
  if (model2Technique) return "MODEL2_ONLY";

  // Compatibility for older stored classification records
  const agreement = String(item.agreement_status || "").toLowerCase();
  const source = String(item.source || "").toLowerCase();

  if (agreement === "not_applicable" || source === "shell_noise") return "MODEL1_NOT_APPLICABLE";
  if (agreement === "exact_technique_agreement" || source === "both") return "AGREE";
  if (agreement.includes("disagreement") || source === "rule_securebert_disagreement") return "DISAGREE";
  if (source === "securebert_unavailable" || model2Unavailable) return "MODEL2_UNAVAILABLE";
  if (agreement === "model_only" || source === "securebert") return "MODEL2_ONLY";

  return "MODEL1_ONLY";
}
