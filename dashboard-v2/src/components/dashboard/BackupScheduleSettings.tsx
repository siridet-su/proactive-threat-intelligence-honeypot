"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { CalendarClock, Clock3, RotateCcw, ShieldCheck } from "lucide-react";

import type { BackupScheduleEdit, BackupSchedulePreview, BackupScheduleSettings, BackupScheduleView } from "@/lib/backupSchedule";

type EditMode = "permanent" | "temporary" | "clear_override";
type PreviewResult = { revision: string; settings: BackupScheduleSettings; preview: BackupSchedulePreview };

function formatBangkok(value: string | null): string {
  if (!value) return "—";
  return new Date(value).toLocaleString("en-GB", {
    timeZone: "Asia/Bangkok", day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function validView(value: unknown): value is BackupScheduleView {
  return Boolean(value && typeof value === "object" && "settings" in value && "preview" in value && "revision" in value);
}

function overrideEndDate(startDate: string, days: number): string {
  return new Date(Date.parse(`${startDate}T00:00:00Z`) + days * 86_400_000).toISOString().slice(0, 10);
}

export function BackupScheduleSettings() {
  const initialized = useRef(false);
  const [view, setView] = useState<BackupScheduleView | null>(null);
  const [mode, setMode] = useState<EditMode>("permanent");
  const [time, setTime] = useState("03:30");
  const [startDate, setStartDate] = useState("");
  const [days, setDays] = useState(7);
  const [preview, setPreview] = useState<PreviewResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const load = useCallback(async () => {
    try {
      const response = await fetch("/api/backup/schedule", { cache: "no-store" });
      const payload: unknown = await response.json();
      if (!response.ok || !validView(payload)) throw new Error("Backup schedule is unavailable");
      setView(payload);
      setError(null);
      if (!initialized.current) {
        setTime(payload.settings.base_time);
        setStartDate(payload.local_date);
        initialized.current = true;
      }
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Backup schedule is unavailable");
    }
  }, []);

  useEffect(() => {
    const initial = window.setTimeout(() => void load(), 0);
    const timer = window.setInterval(() => void load(), 30_000);
    return () => { window.clearTimeout(initial); window.clearInterval(timer); };
  }, [load]);

  function edit(): BackupScheduleEdit {
    if (mode === "clear_override") return { mode };
    if (mode === "temporary") return { mode, time, start_date: startDate, days };
    return { mode, time };
  }

  async function previewChange() {
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      const response = await fetch("/api/backup/schedule/preview", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(edit()),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Could not preview schedule");
      setPreview(payload as PreviewResult);
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Could not preview schedule");
    } finally {
      setBusy(false);
    }
  }

  async function saveChange() {
    if (!preview) return;
    setBusy(true);
    setError(null);
    try {
      const response = await fetch("/api/backup/schedule", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ edit: edit(), expected_revision: preview.revision }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Could not save schedule");
      setView(payload as BackupScheduleView);
      setPreview(null);
      setSaved(true);
      setMode("permanent");
      setTime((payload as BackupScheduleView).settings.base_time);
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Could not save schedule");
      setPreview(null);
      await load();
    } finally {
      setBusy(false);
    }
  }

  const settings = view?.settings;
  const temporary = settings?.override && view && overrideEndDate(settings.override.start_date, settings.override.days) > view.local_date
    ? settings.override : null;
  const editable = Boolean(view?.can_edit && view?.worker_ready);
  return (
    <section className="overflow-hidden rounded-2xl border border-border bg-surface shadow-sm" aria-labelledby="backup-schedule-title">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3 sm:px-5">
        <div className="flex items-center gap-2.5">
          <span className="grid h-9 w-9 place-items-center rounded-lg border border-primary-border bg-primary-subtle text-primary"><CalendarClock className="h-4 w-4" aria-hidden="true" /></span>
          <div>
            <h2 id="backup-schedule-title" className="text-sm font-semibold">Daily backup schedule</h2>
            <p className="mt-0.5 text-xs text-text-muted">One run per day · Asia/Bangkok · all active targets</p>
          </div>
        </div>
        <span className="ui-badge text-xs"><Clock3 className="h-3.5 w-3.5" aria-hidden="true" />Next run {view ? formatBangkok(view.preview.next_run_at) : "checking…"}</span>
      </div>
      <div className="grid gap-5 px-4 py-4 sm:px-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
        <div className="space-y-3 text-sm">
          <div><span className="text-text-muted">Permanent time</span><p className="mt-0.5 font-mono font-semibold text-text">{settings?.base_time ?? "—"}</p></div>
          <div><span className="text-text-muted">Temporary change</span><p className="mt-0.5 text-text">{temporary ? `${temporary.time} · ${temporary.start_date} for ${temporary.days} day${temporary.days === 1 ? "" : "s"}` : "None"}</p></div>
          <div><span className="text-text-muted">Today&apos;s scheduled run</span><p className="mt-0.5 text-text">{view?.today_run_status === "success" ? "Completed" : view?.today_run_status === "running" ? "Running" : view?.today_run_status === "failed" ? "Retry pending" : "Not run yet"}</p></div>
          {temporary && <p className="text-xs text-text-muted">Returns to the permanent time on {formatBangkok(view?.preview.return_at ?? null)}.</p>}
          <p className="text-xs text-text-muted">Archive days use UTC with a two-day safety hold. Coverage follows the latest scheduled run.</p>
          {view?.today_run_status === "running" && <p className="text-xs text-info">Today&apos;s run is in progress. A schedule change will not interrupt it.</p>}
          {!view?.worker_ready && <p className="text-xs text-warning">Pi scheduler is not ready. Changes are unavailable until the control worker is active.</p>}
        </div>
        {view?.can_edit && (
          <div className="space-y-3">
            <fieldset disabled={!editable || busy} className="space-y-3 disabled:opacity-60">
              <legend className="text-sm font-semibold">Change schedule</legend>
              <div className="flex flex-wrap gap-3 text-sm">
                <label className="flex items-center gap-1.5"><input type="radio" name="backup-schedule-mode" checked={mode === "permanent"} onChange={() => { setMode("permanent"); setTime(settings?.base_time ?? "03:30"); setPreview(null); }} />Permanent</label>
                <label className="flex items-center gap-1.5"><input type="radio" name="backup-schedule-mode" checked={mode === "temporary"} onChange={() => { setMode("temporary"); setTime(temporary?.time ?? "01:00"); setStartDate(view.local_date); setDays(temporary?.days ?? 7); setPreview(null); }} />Temporary</label>
                {temporary && <label className="flex items-center gap-1.5"><input type="radio" name="backup-schedule-mode" checked={mode === "clear_override"} onChange={() => { setMode("clear_override"); setPreview(null); }} />Return to permanent</label>}
              </div>
              {mode !== "clear_override" && <label className="block text-xs text-text-muted">Daily time (Bangkok)<input className="ui-field mt-1 w-full" type="time" value={time} onChange={(event) => { setTime(event.target.value); setPreview(null); }} required /></label>}
              {mode === "temporary" && <div className="grid gap-3 sm:grid-cols-2">
                <label className="block text-xs text-text-muted">Start date<input className="ui-field mt-1 w-full" type="date" min={view.local_date} value={startDate} onChange={(event) => { setStartDate(event.target.value); setPreview(null); }} required /></label>
                <label className="block text-xs text-text-muted">Number of days<input className="ui-field mt-1 w-full" type="number" min={1} max={90} value={days} onChange={(event) => { setDays(Number(event.target.value)); setPreview(null); }} required /></label>
              </div>}
              <button type="button" className="ui-button min-h-9 px-3 text-xs" onClick={() => void previewChange()}>Preview change</button>
            </fieldset>
            {preview && <div className="rounded-xl border border-info-border bg-info-subtle p-3 text-xs text-text">
              <p className="font-semibold">Next run: {preview.preview.catch_up ? "as soon as the Pi worker checks the schedule" : formatBangkok(preview.preview.next_run_at)}</p>
              {preview.preview.return_at && <p className="mt-1">Returns to {preview.settings.base_time} on {formatBangkok(preview.preview.return_at)}.</p>}
              <p className="mt-1 text-text-muted">A completed run today will not run twice. An active run will finish before the new schedule takes effect.</p>
              <button type="button" className="ui-button ui-button-primary mt-3 min-h-9 px-3 text-xs" disabled={busy || !editable} onClick={() => void saveChange()}><ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />Save schedule</button>
            </div>}
            {saved && <p className="flex items-center gap-1.5 text-xs text-success"><RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />Schedule saved and queued for the Pi worker.</p>}
          </div>
        )}
        {error && <p role="alert" className="text-xs text-danger lg:col-span-2">{error}</p>}
      </div>
    </section>
  );
}
