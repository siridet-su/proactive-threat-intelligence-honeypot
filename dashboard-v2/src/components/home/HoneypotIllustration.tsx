export default function HoneypotIllustration() {
  return (
    <div className="pti-honeypot-scene relative mx-auto w-full max-w-xl" aria-hidden="true">
      <svg viewBox="0 0 560 440" className="h-auto w-full" role="presentation">
        <circle cx="280" cy="220" r="190" fill="var(--primary-subtle)" />
        <circle cx="280" cy="220" r="142" fill="var(--surface)" stroke="var(--primary-border)" strokeWidth="2" />
        <path d="M143 316 H417" stroke="var(--border)" strokeWidth="2" strokeLinecap="round" />

        <g className="pti-honey-bowl">
          <ellipse cx="280" cy="324" rx="112" ry="24" fill="var(--illustration-honey-deep)" />
          <path d="M170 274 C170 355 208 383 280 383 C352 383 390 355 390 274 Z" fill="var(--surface-raised)" stroke="var(--border-strong)" strokeWidth="3" />
          <ellipse cx="280" cy="274" rx="110" ry="28" fill="var(--illustration-honey)" stroke="var(--illustration-honey-deep)" strokeWidth="3" />
          <ellipse cx="280" cy="269" rx="81" ry="15" fill="var(--illustration-honey-light)" opacity="0.88" />
          <path d="M211 314 H349" stroke="var(--illustration-honey)" strokeWidth="8" strokeLinecap="round" />
          <path d="M229 340 H331" stroke="var(--illustration-honey)" strokeWidth="8" strokeLinecap="round" />
        </g>

        <g className="pti-bee pti-bee-one">
          <ellipse cx="0" cy="0" rx="23" ry="13" fill="var(--illustration-honey)" stroke="var(--illustration-honey-deep)" strokeWidth="3" />
          <path d="M-8 -12 V12 M5 -13 V13" stroke="var(--text)" strokeWidth="4" />
          <ellipse className="pti-bee-wing" cx="-9" cy="-18" rx="13" ry="7" fill="var(--surface)" stroke="var(--primary-border)" strokeWidth="2" />
          <ellipse className="pti-bee-wing" cx="10" cy="-17" rx="13" ry="7" fill="var(--surface)" stroke="var(--primary-border)" strokeWidth="2" />
          <circle cx="18" cy="-2" r="4" fill="var(--text)" />
        </g>

        <g className="pti-bee pti-bee-two">
          <ellipse cx="0" cy="0" rx="18" ry="11" fill="var(--illustration-honey)" stroke="var(--illustration-honey-deep)" strokeWidth="3" />
          <path d="M-5 -10 V10 M7 -10 V10" stroke="var(--text)" strokeWidth="3" />
          <ellipse className="pti-bee-wing" cx="-6" cy="-15" rx="10" ry="5" fill="var(--surface)" stroke="var(--primary-border)" strokeWidth="2" />
          <ellipse className="pti-bee-wing" cx="9" cy="-14" rx="10" ry="5" fill="var(--surface)" stroke="var(--primary-border)" strokeWidth="2" />
          <circle cx="14" cy="-2" r="3" fill="var(--text)" />
        </g>

        <g fill="var(--primary)" opacity="0.78">
          <circle cx="130" cy="132" r="4" /><circle cx="408" cy="118" r="4" /><circle cx="444" cy="273" r="3" />
        </g>
      </svg>
      <div className="pointer-events-none absolute inset-x-10 bottom-1 rounded-xl border border-border bg-surface-raised px-4 py-3 text-center text-sm font-medium text-text shadow-[var(--shadow-card)]">
        A convincing decoy, built to be investigated.
      </div>
    </div>
  );
}
