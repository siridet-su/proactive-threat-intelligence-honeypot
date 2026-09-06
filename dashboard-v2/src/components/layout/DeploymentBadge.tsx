const deploymentLabel = process.env.NEXT_PUBLIC_DASHBOARD_DEPLOYMENT_LABEL?.trim().toUpperCase() || "";
const buildId = process.env.NEXT_PUBLIC_DASHBOARD_BUILD_ID?.trim() || "";
const safeBuildId = buildId.replace(/[^0-9A-Za-z._-]/g, "").slice(0, 12);

export default function DeploymentBadge() {
  if (deploymentLabel !== "STAGING") return null;

  return (
    <div
      aria-label={safeBuildId ? `Staging build ${safeBuildId}` : "Staging build"}
      className="w-full border-b border-warning-border bg-warning-subtle px-4 py-2 text-center text-xs font-semibold text-warning"
      data-deployment-environment="staging"
    >
      STAGING{safeBuildId ? ` · ${safeBuildId}` : ""}
    </div>
  );
}
