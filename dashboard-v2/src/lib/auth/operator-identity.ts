// รูปแบบมาตรฐานสำหรับการตรวจสอบโครงสร้างอีเมลเบื้องต้น
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * เติมเครื่องหมาย \ (Escape) หน้าอักขระพิเศษที่ใช้ใน Regular Expression
 * เพื่อป้องกันช่องโหว่ Regex Injection เมื่อนำข้อมูลจากผู้ใช้มาสร้าง RegExp
 * 
 * @param {string} value - ข้อความที่ต้องการ Escape
 * @returns {string} - ข้อความที่ปลอดภัยสำหรับการสร้าง RegExp
 */
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * ทำความสะอาด (Trim, Lowercase) และตรวจสอบรูปแบบอีเมล
 * 
 * @param {string} value - อีเมลดิบที่รับมาจากฟอร์มหรือ API
 * @returns {string | null} - อีเมลตัวพิมพ์เล็กที่สะอาดแล้ว หรือ null หากรูปแบบไม่ถูกต้อง
 */
export function normalizeEmail(value: string): string | null {
  const email = value.trim().toLowerCase();
  return EMAIL_PATTERN.test(email) ? email : null;
}

/**
 * สร้าง Regular Expression เพื่อใช้ค้นหาอีเมลในฐานข้อมูลแบบพอดีคำ (Exact Match)
 * และไม่สนใจตัวพิมพ์เล็ก-ใหญ่ (Case-insensitive)
 * 
 * @param {string} email - อีเมลที่ต้องการค้นหา
 * @returns {RegExp} - Regular Expression สำหรับค้นหาอีเมลอย่างปลอดภัย
 */
export function emailLookup(email: string): RegExp {
  return new RegExp(`^${escapeRegExp(email)}$`, "i");
}