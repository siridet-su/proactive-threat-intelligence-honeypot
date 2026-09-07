import SessionAwareLink from "@/components/auth/SessionAwareLink";
import ScrollReveal from "@/components/ui/ScrollReveal";

export default function ThreatPreview() {
  return (
    <section aria-labelledby="threat-preview-title" className="pti-threat-preview scroll-mt-24 border-y border-border px-6 py-16 sm:px-10 lg:py-24">
      <div className="mx-auto grid w-full max-w-7xl gap-10 lg:grid-cols-[0.78fr_1.22fr] lg:items-center">
        <ScrollReveal>
          <div className="max-w-xl">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-primary">The swarm</p>
            <h2 id="threat-preview-title" className="mt-4 text-3xl font-semibold tracking-tight sm:text-4xl">Global context stays inside the operator console.</h2>
            <p className="mt-4 text-base leading-7 text-text-muted">The secure workspace connects geographic context with the session evidence that produced it, so investigation can move from an observed signal to its supporting detail.</p>
            <SessionAwareLink href="/login" authenticatedHref="/dashboard" className="ui-button ui-button-primary mt-7 px-6">View live dashboard <span aria-hidden="true">→</span></SessionAwareLink>
          </div>
        </ScrollReveal>

        <ScrollReveal delay={90}>
          <div className="pti-threat-preview-map relative min-h-80 overflow-hidden rounded-3xl border border-primary-border bg-surface-subtle p-5 sm:min-h-96 sm:p-8" aria-label="Stylized global intelligence preview">
            <svg viewBox="0 0 760 400" className="absolute inset-0 h-full w-full" role="img" aria-label="Decorative global signal topology">
              <defs>
                <pattern id="preview-hex-grid" width="50" height="44" patternUnits="userSpaceOnUse">
                  <path d="M12.5 1 37.5 1 50 22 37.5 43 12.5 43 0 22Z" fill="none" stroke="currentColor" strokeWidth="0.8" />
                </pattern>
              </defs>
              <rect width="760" height="400" fill="url(#preview-hex-grid)" className="text-primary" opacity="0.16" />
              <path d="M45 212 C125 165 182 185 251 142 S380 172 444 134 S574 155 708 100" className="pti-preview-stream" fill="none" stroke="var(--info)" strokeWidth="2" strokeLinecap="round" />
              <path d="M54 288 C148 234 231 280 317 223 S494 244 579 195 S653 210 713 242" className="pti-preview-stream pti-preview-stream-delayed" fill="none" stroke="var(--primary)" strokeWidth="2" strokeLinecap="round" />
              <g className="pti-preview-land" fill="var(--surface)" stroke="var(--border-strong)" strokeWidth="1.3">
                <path d="M99 118 166 95 223 117 232 157 204 178 157 164 122 181 82 153Z" />
                <path d="M254 103 316 79 356 104 349 145 322 163 281 150Z" />
                <path d="M360 170 423 149 484 180 477 225 429 245 378 218Z" />
                <path d="M514 112 601 88 669 118 689 166 652 197 582 182 544 203 501 166Z" />
                <path d="M570 247 625 231 666 263 655 308 605 325 562 294Z" />
              </g>
              <g aria-hidden="true">
                <path d="M201 165 253 143 M353 142 420 164 M479 203 577 185 M604 228 611 245" className="pti-preview-connector" fill="none" stroke="var(--primary)" strokeWidth="1.5" />
                <g transform="translate(201 165)" className="pti-preview-marker"><path d="M0 -9 9 0 0 9 -9 0Z" fill="var(--danger)" /><circle r="16" fill="none" stroke="var(--danger)" strokeWidth="1.25" opacity="0.58" /></g>
                <g transform="translate(420 164)" className="pti-preview-marker pti-preview-marker-two"><path d="M0 -8 8 0 0 8 -8 0Z" fill="var(--primary)" /><circle r="14" fill="none" stroke="var(--primary)" strokeWidth="1.25" opacity="0.58" /></g>
                <g transform="translate(611 245)" className="pti-preview-marker pti-preview-marker-three"><path d="M0 -8 8 0 0 8 -8 0Z" fill="var(--warning)" /><circle r="14" fill="none" stroke="var(--warning)" strokeWidth="1.25" opacity="0.58" /></g>
              </g>
            </svg>
            <div className="relative z-10 flex items-start justify-between gap-4">
              <div className="rounded-xl border border-border bg-surface-raised/90 px-4 py-3 shadow-[var(--shadow-card)]">
                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">Intelligence topology</p>
                <p className="mt-1 text-sm text-text-muted">Secure operator view</p>
              </div>
              <span className="ui-badge border-danger-border bg-danger-subtle text-danger"><span className="h-1.5 w-1.5 rounded-full bg-danger" aria-hidden="true" />Protected preview</span>
            </div>
            <div className="absolute bottom-5 left-5 right-5 z-10 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-surface-raised/90 px-4 py-3 text-sm shadow-[var(--shadow-card)]">
              <span className="text-text-muted">Session context, origin mapping, and evidence review.</span>
              <span className="font-mono text-xs text-primary">PTI / INTEL</span>
            </div>
          </div>
        </ScrollReveal>
      </div>
    </section>
  );
}
