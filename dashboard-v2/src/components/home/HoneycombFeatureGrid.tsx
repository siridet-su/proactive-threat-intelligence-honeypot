import { Activity, FileText, Globe2, HeartPulse, type LucideIcon } from "lucide-react";
import SessionAwareLink from "@/components/auth/SessionAwareLink";

interface Feature {
  eyebrow: string;
  title: string;
  description: string;
  action: string;
  icon: LucideIcon;
}

const features: Feature[] = [
  {
    eyebrow: "01",
    title: "Session intelligence",
    description: "Review observed sessions, origin details, classifications, and duration from one queue.",
    action: "Open console",
    icon: Activity,
  },
  {
    eyebrow: "02",
    title: "Origin mapping",
    description: "Use geographic context to move from a broad attack surface to a specific session.",
    action: "View workspace",
    icon: Globe2,
  },
  {
    eyebrow: "03",
    title: "Evidence review",
    description: "Keep captured artifacts and session detail close to the investigation workflow.",
    action: "Review evidence",
    icon: FileText,
  },
  {
    eyebrow: "04",
    title: "Sensor health",
    description: "Monitor the telemetry surface that supports the operator view and its refresh state.",
    action: "Check health",
    icon: HeartPulse,
  },
];

export default function HoneycombFeatureGrid() {
  return (
    <div className="pti-hive-cluster mt-12 grid gap-3 sm:grid-cols-2 lg:mx-auto lg:max-w-5xl lg:grid-cols-4 lg:gap-0">
      {features.map((feature) => {
        const Icon = feature.icon;
        return (
          <div
            key={feature.title}
            className="pti-hive-feature-wrap"
          >
            <SessionAwareLink href="/login" authenticatedHref="/dashboard" className="pti-hive-feature group block h-full focus-visible:outline-none" aria-label={`${feature.action}: ${feature.title}`}>
              <span className="flex items-center justify-between gap-4">
                <span className="font-mono text-xs font-semibold tracking-[0.12em] text-primary">{feature.eyebrow}</span>
                <span className="pti-hive-icon grid h-10 w-10 place-items-center rounded-xl border border-primary-border bg-primary-subtle text-primary" aria-hidden="true"><Icon className="h-5 w-5" /></span>
              </span>
              <h3 className="mt-7 text-lg font-semibold tracking-tight text-text">{feature.title}</h3>
              <p className="mt-3 text-sm leading-6 text-text-muted">{feature.description}</p>
              <span className="mt-6 inline-flex items-center gap-2 text-sm font-semibold text-primary">
                {feature.action}<span aria-hidden="true" className="pti-hive-arrow">→</span>
              </span>
            </SessionAwareLink>
          </div>
        );
      })}
    </div>
  );
}
