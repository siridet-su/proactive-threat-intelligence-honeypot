"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { CalendarClock, Clock3, ShieldCheck } from "lucide-react";

import { ScheduleNumberPicker, ScheduleRangePicker } from "@/components/dashboard/BackupSchedulePickers";
import { OperationToast, type OperationToastKind } from "@/components/ui/OperationToast";
import type { BackupScheduleEdit, BackupSchedulePreview, BackupScheduleSettings, BackupScheduleView } from "@/lib/backupSchedule";

type EditMode = "permanent" | "temporary" | "clear_override";
type PreviewResult = { revision: string; settings: BackupScheduleSettings; preview: BackupSchedulePreview };
const HOURS = Array.from({ length: 24 }, (_, hour) => String(hour).padStart(2, "0"));
const MINUTES = Array.from({ length: 60 }, (_, minute) => String(minute).padStart(2, "0"));
const QUICK_TIMES = ["01:00", "02:00", "03:30"];
const UNDO_DELAY_MS = 3_000;
type ScheduleToast = { kind: OperationToastKind; title: string; description: string; pending?: boolean; undoable?: boolean };

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

function overrideLastDate(startDate: string, days: number): string {
  return new Date(Date.parse(`${startDate}T00:00:00Z`) + (days - 1) * 86_400_000).toISOString().slice(0, 10);
}

export function BackupScheduleSettings() {
  const initialized = useRef(false);
  const pendingSave = useRef<number | null>(null);
  const [view, setView] = useState<BackupScheduleView | null>(null);
  const [mode, setMode] = useState<EditMode>("permanent");
  const [time, setTime] = useState("03:30");
  const [startDate, setStartDate] = useState("");
  const [days, setDays] = useState(7);
  const [preview, setPreview] = useState<PreviewResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<ScheduleToast | null>(null);
  const reducedMotion = useReducedMotion();

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

  useEffect(() => () => {
    if (pendingSave.current !== null) window.clearTimeout(pendingSave.current);
  }, []);

  useEffect(() => {
    if (!toast || toast.pending) return;
    const timer = window.setTimeout(() => setToast(null), 5_000);
    return () => window.clearTimeout(timer);
  }, [toast]);

  function edit(): BackupScheduleEdit {
    if (mode === "clear_override") return { mode };
    if (mode === "temporary") return { mode, time, start_date: startDate, days };
    return { mode, time };
  }

  async function previewChange() {
    setBusy(true);
    setError(null);
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

  async function saveChange(request: { edit: BackupScheduleEdit; expected_revision: string }) {
    setToast({ kind: "info", title: "Saving schedule", description: "Waiting for the Dashboard to confirm the change.", pending: true });
    setError(null);
    try {
      const response = await fetch("/api/backup/schedule", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Could not save schedule");
      setView(payload as BackupScheduleView);
      setPreview(null);
      setToast({ kind: "success", title: "Schedule saved", description: "The new schedule is queued for the Pi worker." });
      setMode("permanent");
      setTime((payload as BackupScheduleView).settings.base_time);
    } catch (reason: unknown) {
      const message = reason instanceof Error ? reason.message : "Could not save schedule";
      setError(message);
      setToast({ kind: "error", title: "Schedule was not saved", description: message });
      setPreview(null);
      await load();
    } finally {
      setBusy(false);
    }
  }

  function queueSave() {
    if (!preview || pendingSave.current !== null || busy) return;
    const request = { edit: edit(), expected_revision: preview.revision };
    setBusy(true);
    setError(null);
    setToast({ kind: "info", title: "Schedule change pending", description: "Saving in 3 seconds. Select Undo to cancel before it reaches the Pi worker.", pending: true, undoable: true });
    pendingSave.current = window.setTimeout(() => {
      pendingSave.current = null;
      void saveChange(request);
    }, UNDO_DELAY_MS);
  }

  function undoSave() {
    if (pendingSave.current === null) return;
    window.clearTimeout(pendingSave.current);
    pendingSave.current = null;
    setBusy(false);
    setToast(null);
  }

  const settings = view?.settings;
  const temporary = settings?.override && view && overrideEndDate(settings.override.start_date, settings.override.days) > view.local_date
    ? settings.override : null;
  const editable = Boolean(view?.can_edit && view?.worker_ready);
  const [selectedHour = "03", selectedMinute = "30"] = time.split(":");
  function changeTime(next: string) {
    setTime(next);
    setPreview(null);
  }
  function selectTemporaryMode() {
    if (!view) return;
    setMode("temporary");
    changeTime(temporary?.time ?? "01:00");
    const draftStart = temporary && temporary.start_date > view.local_date ? temporary.start_date : view.local_date;
    const remainingDays = temporary
      ? Math.max(1, Math.round((Date.parse(`${overrideEndDate(temporary.start_date, temporary.days)}T00:00:00Z`) - Date.parse(`${draftStart}T00:00:00Z`)) / 86_400_000))
      : 7;
    setStartDate(draftStart);
    setDays(remainingDays);
  }
  return (
    <section className="relative z-20 rounded-2xl border border-border bg-surface shadow-sm" aria-labelledby="backup-schedule-title">
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
        <div className="space-y-3 rounded-xl border border-border bg-surface-subtle p-4 text-sm">
          <div><span className="text-text-muted">Permanent time</span><p className="mt-0.5 font-mono font-semibold text-text">{settings?.base_time ?? "—"}</p></div>
          <div><span className="text-text-muted">Temporary change</span><p className="mt-0.5 text-text">{temporary ? `${temporary.time} · ${temporary.start_date} – ${overrideLastDate(temporary.start_date, temporary.days)} (${temporary.days} day${temporary.days === 1 ? "" : "s"})` : "None"}</p></div>
          <div><span className="text-text-muted">Today&apos;s scheduled run</span><p className="mt-0.5 text-text">{view?.today_run_status === "success" ? "Completed" : view?.today_run_status === "running" ? "Running" : view?.today_run_status === "failed" ? "Retry pending" : "Not run yet"}</p></div>
          {temporary && <p className="text-xs text-text-muted">Returns to the permanent time on {formatBangkok(view?.preview.return_at ?? null)}.</p>}
          <p className="text-xs text-text-muted">Archive days use UTC with a two-day safety hold. Coverage follows the latest scheduled run.</p>
          {view?.today_run_status === "running" && <p className="text-xs text-info">Today&apos;s run is in progress. A schedule change will not interrupt it.</p>}
          {!view?.worker_ready && <p className="text-xs text-warning">Pi scheduler is not ready. Changes are unavailable until the control worker is active.</p>}
        </div>
        {view?.can_edit && (
          <div className="space-y-4 rounded-xl border border-border bg-surface-subtle p-4">
            <fieldset disabled={!editable || busy} className="space-y-3 disabled:opacity-60">
              <legend className="text-sm font-semibold">Change schedule</legend>
              <div className="flex flex-wrap gap-2 text-sm">
                <label className={`flex min-h-10 cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 transition-colors ${mode === "permanent" ? "border-primary-border bg-primary-subtle text-text" : "border-border bg-surface text-text-muted hover:border-primary-border"}`}><input className="accent-primary" type="radio" name="backup-schedule-mode" checked={mode === "permanent"} onChange={() => { setMode("permanent"); changeTime(settings?.base_time ?? "03:30"); }} />Permanent</label>
                <label className={`flex min-h-10 cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 transition-colors ${mode === "temporary" ? "border-primary-border bg-primary-subtle text-text" : "border-border bg-surface text-text-muted hover:border-primary-border"}`}><input className="accent-primary" type="radio" name="backup-schedule-mode" checked={mode === "temporary"} onChange={selectTemporaryMode} />Temporary</label>
                {temporary && <label className={`flex min-h-10 cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 transition-colors ${mode === "clear_override" ? "border-primary-border bg-primary-subtle text-text" : "border-border bg-surface text-text-muted hover:border-primary-border"}`}><input className="accent-primary" type="radio" name="backup-schedule-mode" checked={mode === "clear_override"} onChange={() => { setMode("clear_override"); changeTime(settings?.base_time ?? "03:30"); }} />Return to permanent</label>}
              </div>
              <div className="rounded-lg border border-border bg-surface p-3">
                <p className="text-xs font-medium text-text-muted">{mode === "clear_override" ? "Permanent time resumes · Asia/Bangkok (24-hour)" : "Daily time · Asia/Bangkok (24-hour)"}</p>
                <div className="mt-2 flex items-center gap-2">
                  <ScheduleNumberPicker label="Hour" value={selectedHour} values={HOURS} disabled={!editable || busy || mode === "clear_override"} onChange={(hour) => changeTime(`${hour}:${selectedMinute}`)} />
                  <span className="pt-4 text-lg font-semibold text-text-muted" aria-hidden="true">:</span>
                  <ScheduleNumberPicker label="Minute" value={selectedMinute} values={MINUTES} disabled={!editable || busy || mode === "clear_override"} onChange={(minute) => changeTime(`${selectedHour}:${minute}`)} />
                </div>
                <div className="mt-3 flex flex-wrap items-center gap-1.5 text-xs">
                  <span className="mr-1 text-text-muted">Quick times</span>
                  {QUICK_TIMES.map((quickTime) => <button key={quickTime} type="button" disabled={mode === "clear_override"} aria-pressed={time === quickTime} onClick={() => changeTime(quickTime)} className={`rounded-md border px-2.5 py-1 font-mono transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${time === quickTime ? "border-primary-border bg-primary-subtle text-primary" : "border-border bg-surface-subtle text-text-muted hover:border-primary-border hover:text-text"}`}>{quickTime}</button>)}
                </div>
              </div>
              <div className="relative h-[68px]">
              <AnimatePresence initial={false}>
                {mode === "temporary" ? <motion.div key="temporary-range" className="absolute inset-x-0 top-0" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={reducedMotion ? { duration: 0 } : { duration: 0.15 }}>
                  <ScheduleRangePicker startDate={startDate} durationDays={days} today={view.local_date} disabled={!editable || busy} onChange={(day, duration) => { setStartDate(day); setDays(duration); setPreview(null); }} />
                </motion.div> : <motion.div key={mode} className="absolute inset-x-0 top-0" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={reducedMotion ? { duration: 0 } : { duration: 0.15 }}>
                  <span className="text-xs text-text-muted">{mode === "clear_override" ? "Effect" : "Applies for"}</span>
                  <div className="ui-field mt-1 flex items-center text-sm">{mode === "clear_override" ? "Return to the permanent schedule after saving" : temporary ? "Ongoing base time · temporary dates stay in effect" : "Every day until changed"}</div>
                </motion.div>}
              </AnimatePresence>
              </div>
              <button type="button" className="ui-button min-h-9 px-3 text-xs" onClick={() => void previewChange()}>Preview change</button>
            </fieldset>
            {preview && <div className="rounded-xl border border-info-border bg-info-subtle p-3 text-xs text-text">
              <p className="font-semibold">Next run: {preview.preview.catch_up ? "as soon as the Pi worker checks the schedule" : formatBangkok(preview.preview.next_run_at)}</p>
              {preview.preview.return_at && <p className="mt-1">Returns to {preview.settings.base_time} on {formatBangkok(preview.preview.return_at)}.</p>}
              <p className="mt-1 text-text-muted">A completed run today will not run twice. An active run will finish before the new schedule takes effect.</p>
              <button type="button" className="ui-button ui-button-primary mt-3 min-h-9 px-3 text-xs" disabled={busy || !editable} onClick={queueSave}><ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />Save schedule</button>
            </div>}
          </div>
        )}
        {error && <p role="alert" className="text-xs text-danger lg:col-span-2">{error}</p>}
      </div>
      <AnimatePresence>
        {toast && <OperationToast key="backup-schedule-toast" kind={toast.kind} title={toast.title} description={toast.description} onDismiss={() => setToast(null)} actionLabel={toast.undoable ? "Undo" : undefined} onAction={undoSave} dismissible={!toast.pending} />}
      </AnimatePresence>
    </section>
  );
}
