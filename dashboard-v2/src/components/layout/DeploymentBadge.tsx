/**
 * คอมโพเนนต์สำหรับแสดงแถบแจ้งเตือน (Badge) ว่าระบบกำลังทำงานอยู่ในโหมด STAGING
 * หากไม่ใช่โหมด STAGING จะไม่แสดงผลใดๆ (return null)
 *
 * @returns {JSX.Element | null} แถบแจ้งเตือนพร้อม Build ID หรือ null
 */
export default function DeploymentBadge() {
  // ดึงค่าจาก Environment Variables ไว้ภายใน Component เพื่อให้สามารถจำลอง (Mock) ใน Unit Test ได้
  const deploymentLabel = process.env.NEXT_PUBLIC_DASHBOARD_DEPLOYMENT_LABEL?.trim().toUpperCase() || "";
  const buildId = process.env.NEXT_PUBLIC_DASHBOARD_BUILD_ID?.trim() || "";
  
  // กรองเฉพาะตัวอักษรที่ปลอดภัย (a-z, 0-9, จุด, ขีดล่าง, ยัติภังค์) และจำกัดความยาวสูงสุด 12 ตัวอักษร
  const safeBuildId = buildId.replace(/[^0-9A-Za-z._-]/g, "").slice(0, 12);

  if (deploymentLabel !== "STAGING") return null;

  return (
    <div
      aria-label={safeBuildId ? `Staging build ${safeBuildId}` : "Staging build"}
      className="w-full border-b border-warning-border bg-warning-subtle px-4 py-2 text-center text-xs font-semibold text-warning"
      data-deployment-environment="staging"
    >
      STAGING{safeBuildId ? `   ${safeBuildId}` : ""}
    </div>
  );
}