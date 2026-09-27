"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, Clock3, RefreshCw, ShieldCheck, Terminal } from "lucide-react";

import { RegionState } from "@/components/ui/RegionState";
import type { FilesystemTopologySession } from "@/lib/dashboardTypes";
import { formatTimestamp } from "./filesystemUtils";

const COMMAND_EVENT_IDS = new Set([
  "cowrie.command.failed",
  "cowrie.command.input",
  "cowrie.command.success",
]);
const CANONICAL_SESSION_ID_PATTERN = /^session_v1_[0-9a-f]{32}$/;

interface CommandEvidenceEvent {
  event_id: string;
  eventid: "cowrie.command.failed" | "cowrie.command.input" | "cowrie.command.success";
  timestamp: string | null;
  input: string;
  command_text_available: boolean;
  input_truncated: boolean;
}

interface CommandEvidenceProjection {
  session_id: string;
  historical_originals: "unrecoverable_if_redacted_before_persistence";
  commands: CommandEvidenceEvent[];
  truncated: boolean;
}

type LoadResult =
  | { sessionId: string; status: "ready"; projection: CommandEvidenceProjection }
  | { sessionId: string; status: "unauthorized" }
  | { sessionId: string; status: "forbidden" }
  | { sessionId: string; status: "unavailable"; message: string }
  | { sessionId: string; status: "error"; message: string };

interface CommandEvidencePanelProps {
  selectedSession: FilesystemTopologySession;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseProjection(value: unknown, expectedSessionId: string): CommandEvidenceProjection | null {
  if (
    !isRecord(value)
    || value.ok !== true
    || value.schema_version !== "dashboard.admin_cowrie_commands.v2"
    || value.requested_session_id !== expectedSessionId
    || typeof value.session_id !== "string"
    || !CANONICAL_SESSION_ID_PATTERN.test(value.session_id)
    || value.sensitive !== true
    || value.content_scope !== "administrator_only_cowrie_command_input"
    || value.historical_originals !== "unrecoverable_if_redacted_before_persistence"
    || typeof value.truncated !== "boolean"
    || !Array.isArray(value.commands)
    || value.commands.length > 100
  ) return null;

  const commands: CommandEvidenceEvent[] = [];
  const seenEventIds = new Set<string>();
  for (const candidate of value.commands) {
    if (
      !isRecord(candidate)
      || typeof candidate.event_id !== "string"
      || candidate.event_id.length === 0
      || candidate.event_id.length > 256
      || seenEventIds.has(candidate.event_id)
      || typeof candidate.eventid !== "string"
      || !COMMAND_EVENT_IDS.has(candidate.eventid)
      || (candidate.timestamp !== null && (typeof candidate.timestamp !== "string" || candidate.timestamp.length > 64))
      || typeof candidate.input !== "string"
      || candidate.input.length > 8_192
      || typeof candidate.command_text_available !== "boolean"
      || typeof candidate.input_truncated !== "boolean"
    ) return null;

    seenEventIds.add(candidate.event_id);
    const isRedacted = candidate.input.trim() === "[REDACTED]";
    const commandTextAvailable = candidate.command_text_available && candidate.input.length > 0 && !isRedacted;
    commands.push({
      event_id: candidate.event_id,
      eventid: candidate.eventid as CommandEvidenceEvent["eventid"],
      timestamp: candidate.timestamp as string | null,
      input: commandTextAvailable ? candidate.input : isRedacted ? "[REDACTED]" : "",
      command_text_available: commandTextAvailable,
      input_truncated: candidate.input_truncated,
    });
  }

  return {
    session_id: expectedSessionId,
    historical_originals: "unrecoverable_if_redacted_before_persistence",
    commands,
    truncated: value.truncated,
  };
}

function responseError(status: number):
  | { status: "unauthorized" }
  | { status: "forbidden" }
  | { status: "unavailable"; message: string } {
  if (status === 401) return { status: "unauthorized" };
  if (status === 403) return { status: "forbidden" };
  if (status === 400) {
    return {
      status: "unavailable",
      message: "No verified canonical session mapping is available. Command evidence was not queried.",
    };
  }
  if (status === 503) {
    return {
      status: "unavailable",
      message: "The protected command evidence source is temporarily unavailable or not configured.",
    };
  }
  return { status: "unavailable", message: `Command evidence could not be loaded (HTTP ${status}).` };
}

function displayInput(value: string): string {
  return Array.from(value, (character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    const isAllowedWhitespace = character === "\n" || character === "\r" || character === "\t";
    const isControl = (codePoint <= 0x1f && !isAllowedWhitespace)
      || (codePoint >= 0x7f && codePoint <= 0x9f)
      || codePoint === 0x00ad
      || codePoint === 0x061c
      || codePoint === 0x180e
      || (codePoint >= 0x200b && codePoint <= 0x200f)
      || (codePoint >= 0x202a && codePoint <= 0x202e)
      || (codePoint >= 0x2060 && codePoint <= 0x206f)
      || codePoint === 0xfeff;
    return isControl ? `\\u{${codePoint.toString(16)}}` : character;
  }).join("");
}

function sortCommandEvents(commands: CommandEvidenceEvent[]): CommandEvidenceEvent[] {
  return [...commands].sort((left, right) => {
    const leftTime = left.timestamp ? Date.parse(left.timestamp) : Number.NaN;
    const rightTime = right.timestamp ? Date.parse(right.timestamp) : Number.NaN;
    const leftValid = Number.isFinite(leftTime);
    const rightValid = Number.isFinite(rightTime);
    if (leftValid && rightValid && leftTime !== rightTime) return leftTime - rightTime;
    if (leftValid !== rightValid) return leftValid ? -1 : 1;
    return left.event_id.localeCompare(right.event_id);
  });
}

function eventLabel(eventid: CommandEvidenceEvent["eventid"]): string {
  if (eventid === "cowrie.command.input") return "Command input event";
  if (eventid === "cowrie.command.failed") return "Cowrie command failure event";
  return "Cowrie command success event";
}

export function CommandEvidencePanel({ selectedSession }: CommandEvidencePanelProps) {
  const [result, setResult] = useState<LoadResult | null>(null);
  const [retryCount, setRetryCount] = useState(0);
  const sessionId = selectedSession.sessionId;
  const currentResult = result?.sessionId === sessionId ? result : null;

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    void (async () => {
      try {
        const response = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/commands`, {
          method: "GET",
          cache: "no-store",
          credentials: "same-origin",
          headers: { Accept: "application/json" },
          signal: controller.signal,
        });

        if (response.redirected) {
          if (active) setResult({ sessionId, status: "unauthorized" });
          return;
        }

        if (!response.ok) {
          const failure = responseError(response.status);
          if (active) {
            setResult(failure.status === "unauthorized"
              ? { sessionId, status: "unauthorized" }
              : failure.status === "forbidden"
                ? { sessionId, status: "forbidden" }
                : { sessionId, status: "unavailable", message: failure.message });
          }
          return;
        }

        if (!(response.headers.get("content-type") ?? "").toLowerCase().includes("application/json")) {
          if (active) {
            setResult({
              sessionId,
              status: "error",
              message: "The protected endpoint did not return command evidence JSON. Sign in again or contact an administrator.",
            });
          }
          return;
        }

        const payload: unknown = await response.json();
        const projection = parseProjection(payload, sessionId);
        if (!projection) {
          if (active) setResult({ sessionId, status: "error", message: "The command evidence response did not match this session or its expected schema." });
          return;
        }
        if (active) setResult({ sessionId, status: "ready", projection });
      } catch {
        if (!active || controller.signal.aborted) return;
        setResult({ sessionId, status: "error", message: "The command evidence request failed. Retry to load this session again." });
      }
    })();

    return () => {
      active = false;
      controller.abort();
    };
  }, [sessionId, retryCount]);

  const projection = currentResult?.status === "ready" ? currentResult.projection : null;
  const commands = projection ? sortCommandEvents(projection.commands) : [];

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3" data-testid="command-evidence-panel">
      <section className="rounded-xl border border-border bg-surface-subtle p-3" aria-label="Command evidence scope">
        <div className="flex items-center gap-2 text-xs font-semibold text-text">
          <ShieldCheck className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
          <span>Session-scoped command evidence</span>
          <span className="ml-auto rounded-full border border-warning-border bg-warning-subtle px-2 py-0.5 text-xs text-warning">Admin only</span>
        </div>
        <dl className="mt-2 grid gap-2 text-xs sm:grid-cols-2">
          <div className="min-w-0 sm:col-span-2">
            <dt className="text-text-subtle">Session ID</dt>
            <dd className="mt-0.5 break-all font-mono text-text">{selectedSession.sessionId}</dd>
          </div>
          <div>
            <dt className="text-text-subtle">Source IP</dt>
            <dd className="mt-0.5 font-mono text-text">{selectedSession.sourceIp}</dd>
          </div>
          <div>
            <dt className="text-text-subtle">Evidence source</dt>
            <dd className="mt-0.5 text-text">Cowrie command events</dd>
          </div>
        </dl>
        <div className="mt-2 space-y-1.5 border-t border-border pt-2 text-xs leading-relaxed text-text-muted">
          <p>Command input is session-level evidence. It is not automatically linked to the selected CWD hop and does not prove the command succeeded or that a file was read or written.</p>
          <p>Command input redacted before persistence cannot be reconstructed. File-operation events are not available in this view.</p>
        </div>
      </section>

      <section className="flex min-h-0 flex-1 flex-col rounded-xl border border-border bg-surface p-3" aria-label="Cowrie command events">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
          <div className="flex items-center gap-1.5 font-semibold text-text">
            <Terminal className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
            <span>Command events</span>
          </div>
          <span className="font-mono text-text-subtle">{projection ? `${commands.length} returned` : "Session scoped"}</span>
        </div>

        {currentResult?.status === "ready" && currentResult.projection.truncated && (
          <div role="status" className="mt-2 rounded-lg border border-warning-border bg-warning-subtle px-2.5 py-2 text-xs text-warning">
            The protected response is bounded or truncated. Some events may be omitted, and individual shortened inputs are marked below.
          </div>
        )}

        {!currentResult ? (
          <div className="mt-3"><RegionState kind="loading" title="Loading command evidence" /></div>
        ) : currentResult.status === "unauthorized" ? (
          <div className="mt-3"><RegionState kind="error" title="Sign in required" description="Sign in with an account authorized to review this protected command evidence." /></div>
        ) : currentResult.status === "forbidden" ? (
          <div className="mt-3"><RegionState kind="error" title="Administrator access required" description="Raw Cowrie command input is restricted to administrators. No command text was returned." /></div>
        ) : currentResult.status === "unavailable" || currentResult.status === "error" ? (
          <div className="mt-3 flex min-h-40 flex-col items-center justify-center gap-3 rounded-xl border border-danger-border/40 bg-danger-subtle p-5 text-center">
            <AlertTriangle className="h-5 w-5 text-danger" aria-hidden="true" />
            <p role="alert" className="max-w-md text-xs text-text-muted">{currentResult.message}</p>
            <button
              type="button"
              className="ui-button"
              onClick={() => {
                setResult(null);
                setRetryCount((count) => count + 1);
              }}
            >
              <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
              Retry
            </button>
          </div>
        ) : commands.length === 0 ? (
          <div className="mt-3"><RegionState kind="empty" title="No command events returned" description="No Cowrie command events were returned for this session. This result does not establish that the session had no other activity." /></div>
        ) : (
          <ol className="mt-3 min-h-0 flex-1 space-y-2 overflow-y-auto overscroll-contain pr-1 pb-2" aria-label="Session command evidence">
            {commands.map((command) => {
              const isRedacted = command.input.trim() === "[REDACTED]";
              const commandTextVisible = command.command_text_available && command.input.length > 0 && !isRedacted;
              return (
                <li key={command.event_id}>
                  <article className="rounded-lg border border-border bg-surface-subtle p-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1">
                      <span className="text-xs font-semibold text-text">{eventLabel(command.eventid)}</span>
                      <time className="inline-flex items-center gap-1 font-mono text-xs text-text-subtle" dateTime={command.timestamp ?? undefined}>
                        <Clock3 className="h-3 w-3" aria-hidden="true" />
                        {formatTimestamp(command.timestamp)}
                      </time>
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-1.5 text-xs">
                      <span className="rounded border border-border bg-surface px-1.5 py-0.5 font-mono text-text-subtle">{command.eventid}</span>
                      <span className="break-all font-mono text-text-subtle">Event ID: {command.event_id}</span>
                      {command.input_truncated && (
                        <span className="rounded border border-warning-border bg-warning-subtle px-1.5 py-0.5 font-medium text-warning">Input truncated</span>
                      )}
                    </div>
                    {commandTextVisible ? (
                      <pre dir="ltr" className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-surface px-2.5 py-2 font-mono text-xs leading-relaxed text-text">
                        {displayInput(command.input)}
                      </pre>
                    ) : (
                      <p className="mt-2 rounded-md border border-border bg-surface px-2.5 py-2 text-xs text-text-muted">
                        {isRedacted
                          ? "Input was redacted before persistence; the original text is unavailable."
                          : "No command input text is present in this retained event."}
                      </p>
                    )}
                  </article>
                </li>
              );
            })}
          </ol>
        )}
      </section>
    </div>
  );
}
