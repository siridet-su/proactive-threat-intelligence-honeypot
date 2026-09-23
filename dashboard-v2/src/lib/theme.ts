export type ThemePreference = "system" | "light" | "dark";
export type ResolvedTheme = Exclude<ThemePreference, "system">;
export type ThemeTransitionRequest = { theme: ResolvedTheme };

export const THEME_STORAGE_KEY = "pti-theme";
export const THEME_CHANGE_EVENT = "pti-theme-change";
export const THEME_TRANSITION_REQUEST_EVENT = "pti-theme-transition-request";

/**
 * ตรวจสอบและแปลงค่าธีมที่ได้รับ ให้อยู่ในรูปแบบที่ถูกต้องเสมอ
 * 
 * @param {string | null | undefined} value - ค่าธีมดิบที่ต้องการตรวจสอบ
 * @returns {ThemePreference} ค่าธีมที่ถูกต้อง ("light", "dark", หรือ "system")
 */
export function parseTheme(value: string | null | undefined): ThemePreference {
  return value === "light" || value === "dark" ? value : "system";
}

/**
 * ประมวลผลค่าธีมที่เลือก หากผู้ใช้เลือก "system" ระบบจะตรวจสอบการตั้งค่าของ OS แทน
 * 
 * @param {ThemePreference} preference - ค่าธีมเป้าหมาย
 * @returns {ResolvedTheme} ค่าธีมที่ควรนำไปแสดงผลจริง ("light" หรือ "dark")
 */
export function resolveTheme(preference: ThemePreference): ResolvedTheme {
  if (preference === "system") {
    // ป้องกัน Error หากฟังก์ชันนี้ถูกรันในฝั่ง Server (SSR)
    if (typeof window !== "undefined" && window.matchMedia) {
      return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }
    return "light"; // ค่า Fallback
  }
  return preference;
}

/**
 * ปรับเปลี่ยนคลาสและ data-attribute ในระดับ DOM (HTML tag) เพื่ออัปเดตหน้าจอทันที
 * 
 * @param {ThemePreference} preference - ค่าธีมที่ต้องการใช้งาน
 */
export function applyTheme(preference: ThemePreference) {
  const resolved = resolveTheme(preference);
  document.documentElement.dataset.theme = resolved;
  document.documentElement.dataset.themePreference = preference;
  document.documentElement.style.colorScheme = resolved;
}

/**
 * บันทึกการตั้งค่าธีมลงใน LocalStorage พร้อมเรียกใช้การอัปเดตหน้าจอและปล่อย Event 
 * เพื่อให้ React Components รับรู้การเปลี่ยนแปลง
 * 
 * @param {ThemePreference} preference - ค่าธีมที่ต้องการบันทึก
 */
export function setThemePreference(preference: ThemePreference) {
  try { 
    localStorage.setItem(THEME_STORAGE_KEY, preference); 
  } catch { 
    /* ยอมให้ทำงานต่อไปกรณีเบราว์เซอร์บล็อกการใช้งาน Storage */ 
  }
  applyTheme(preference);
  window.dispatchEvent(new Event(THEME_CHANGE_EVENT));
}

/**
 * ยิง Event แจ้งความจำนงในการเปลี่ยนธีม (มักถูกดักจับโดย ThemeProvider เพื่อเล่นแอนิเมชันเปลี่ยนธีม)
 * 
 * @param {ResolvedTheme} theme - ค่าธีมสว่างหรือมืดที่ต้องการเปลี่ยน
 */
export function requestThemePreference(theme: ResolvedTheme) {
  window.dispatchEvent(new CustomEvent<ThemeTransitionRequest>(THEME_TRANSITION_REQUEST_EVENT, {
    detail: { theme },
  }));
}

// Script แบบทำงานทันทีสำหรับใส่ใน <head> เพื่อป้องกันอาการจอกะพริบ (FOUC) ระหว่างโหลด
export const themeBootstrap = `(${function () {
  let preference = "system";
  try {
    const stored = localStorage.getItem("pti-theme");
    if (stored === "light" || stored === "dark") preference = stored;
  } catch {}
  const resolved = preference === "system" ? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light") : preference;
  const root = document.documentElement;
  root.dataset.theme = resolved;
  root.dataset.themePreference = preference;
  root.style.colorScheme = resolved;
}.toString()})();`;