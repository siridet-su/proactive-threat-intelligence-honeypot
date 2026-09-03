const deploymentLabel = process.env.NEXT_PUBLIC_DASHBOARD_DEPLOYMENT_LABEL?.trim().toUpperCase() || "";
const buildId = process.env.NEXT_PUBLIC_DASHBOARD_BUILD_ID?.trim() || "";
const safeBuildId = buildId.replace(/[^0-9A-Za-z._-]/g, "").slice(0, 12);

export default function DeploymentBadge() {
  if (deploymentLabel !== "STAGING") return null;

  return (
    <div
      aria-label={safeBuildId ? `Staging build ${safeBuildId}` : "Staging build"}
      className="fixed right-3 top-3 z-[100] rounded border border-amber-400/60 bg-amber-950/90 px-2 py-1 text-[10px] font-bold tracking-[0.18em] text-amber-200 shadow-lg"
      data-deployment-environment="staging"
    >
      STAGING{safeBuildId ? ` · ${safeBuildId}` : ""}
    </div>
  );
}
