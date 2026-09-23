import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * รวมและจัดรูปแบบ CSS Classes สำหรับ Tailwind CSS
 * โดยใช้ clsx เพื่อรองรับการเขียนคลาสแบบมีเงื่อนไข (Conditional) 
 * และใช้ twMerge เพื่อลบคลาสที่ซ้ำซ้อนหรือขัดแย้งกันออก (เช่น p-4 p-2 จะเหลือแค่ p-2)
 * 
 * @param {...ClassValue[]} inputs - รายการคลาส (String, Array, หรือ Object แบบมีเงื่อนไข)
 * @returns {string} - สตริงของคลาสที่ถูกรวมและตัดส่วนที่ขัดแย้งกันออกแล้ว
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}