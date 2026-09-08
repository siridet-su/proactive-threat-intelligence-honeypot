"use client";

import * as AlertDialog from "@radix-ui/react-alert-dialog";
import { LoaderCircle } from "lucide-react";

interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: () => void | Promise<void>;
  title: string;
  description: string;
  confirmLabel: string;
  confirmVariant?: "primary" | "danger";
  isProcessing?: boolean;
  processingLabel?: string;
  errorMessage?: string;
}

export function ConfirmDialog({ open, onOpenChange, onConfirm, title, description, confirmLabel, confirmVariant = "primary", isProcessing = false, processingLabel, errorMessage }: ConfirmDialogProps) {
  return (
    <AlertDialog.Root open={open} onOpenChange={(nextOpen) => { if (!isProcessing) onOpenChange(nextOpen); }}>
      <AlertDialog.Portal>
        <AlertDialog.Overlay className="fixed inset-0 z-[130] bg-[var(--scrim)] data-[state=open]:animate-[pti-fade-in_150ms_ease-out]" />
        <AlertDialog.Content className="fixed left-1/2 top-1/2 z-[131] w-[calc(100%-2rem)] max-w-md -translate-x-1/2 -translate-y-1/2 rounded-2xl border border-border bg-surface p-6 text-text shadow-[var(--shadow-raised)] data-[state=open]:animate-[pti-dialog-in_150ms_ease-out]">
          <AlertDialog.Title className="text-lg font-semibold">{title}</AlertDialog.Title>
          <AlertDialog.Description className="mt-2 text-sm leading-6 text-text-muted">{description}</AlertDialog.Description>
          {errorMessage && <p role="alert" className="mt-4 rounded-lg border border-danger-border bg-danger-subtle p-3 text-sm text-danger">{errorMessage}</p>}
          <div className="mt-6 flex flex-wrap justify-end gap-3">
            <AlertDialog.Cancel asChild><button className="ui-button" disabled={isProcessing}>Cancel</button></AlertDialog.Cancel>
            <button type="button" onClick={() => void onConfirm()} disabled={isProcessing} className={confirmVariant === "danger" ? "ui-button ui-button-danger" : "ui-button ui-button-primary"}>
              {isProcessing && <LoaderCircle className="h-4 w-4 motion-safe:animate-spin" aria-hidden="true" />}
              {isProcessing ? processingLabel ?? "Processing…" : confirmLabel}
            </button>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}
