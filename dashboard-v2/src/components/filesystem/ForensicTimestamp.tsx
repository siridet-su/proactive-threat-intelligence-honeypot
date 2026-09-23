"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";

import {
  deriveForensicTimestamp,
  type ForensicTimestampLabel,
} from "./filesystemUtils";

interface ForensicTimestampRowProps {
  label: ForensicTimestampLabel;
  value: string | null | undefined;
  copyable?: boolean;
  className?: string;
}

export function ForensicTimestampRow({
  label,
  value,
  copyable = false,
  className = "",
}: ForensicTimestampRowProps) {
  const timestamp = deriveForensicTimestamp(label, value);
  const [copiedIso, setCopiedIso] = useState<string | null>(null);

  const copyIsoTimestamp = async () => {
    if (!timestamp.iso) return;
    try {
      await navigator.clipboard.writeText(timestamp.iso);
      setCopiedIso(timestamp.iso);
    } catch {
      setCopiedIso(null);
    }
  };

  return (
    <div
      data-forensic-time-row={label}
      className={`flex items-center justify-between gap-2 ${className}`}
    >
      <dt className="text-xs text-text-subtle">{label}</dt>
      <dd className="flex min-w-0 items-center justify-end gap-1.5 text-right text-xs text-text-muted">
        {timestamp.available && timestamp.iso ? (
          <time
            data-forensic-time-kind={label}
            dateTime={timestamp.iso}
            title={`${label} evidence timestamp: ${timestamp.iso}`}
            className="min-w-0 break-words"
          >
            {timestamp.absolute}
          </time>
        ) : (
          <span>{timestamp.absolute}</span>
        )}
        {copyable && timestamp.iso ? (
          <button
            type="button"
            onClick={() => void copyIsoTimestamp()}
            aria-label={`Copy ${label} ISO timestamp`}
            data-tooltip-label={`Copy ${label} ISO timestamp`}
            data-keyboard-tooltip
            className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-surface text-text-muted transition-colors hover:bg-surface-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          >
            {copiedIso === timestamp.iso ? <Check className="h-3.5 w-3.5 text-success" aria-hidden="true" /> : <Copy className="h-3.5 w-3.5" aria-hidden="true" />}
          </button>
        ) : null}
      </dd>
    </div>
  );
}
