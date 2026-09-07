"use client";

import * as AlertDialog from "@radix-ui/react-alert-dialog";

interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: () => void;
  title: string;
  description: string;
  confirmLabel: string;
  confirmVariant?: "primary" | "danger";
}

export function ConfirmDialog({ open, onOpenChange, onConfirm, title, description, confirmLabel, confirmVariant = "primary" }: ConfirmDialogProps) {
  return (
    <AlertDialog.Root open={open} onOpenChange={onOpenChange}>
      <AlertDialog.Portal>
        <AlertDialog.Overlay className="fixed inset-0 z-[130] bg-[var(--scrim)] data-[state=open]:animate-[pti-fade-in_150ms_ease-out]" />
        <AlertDialog.Content className="fixed left-1/2 top-1/2 z-[131] w-[calc(100%-2rem)] max-w-md -translate-x-1/2 -translate-y-1/2 rounded-2xl border border-border bg-surface p-6 text-text shadow-[var(--shadow-raised)] data-[state=open]:animate-[pti-dialog-in_150ms_ease-out]">
          <AlertDialog.Title className="text-lg font-semibold">{title}</AlertDialog.Title>
          <AlertDialog.Description className="mt-2 text-sm leading-6 text-text-muted">{description}</AlertDialog.Description>
          <div className="mt-6 flex flex-wrap justify-end gap-3">
            <AlertDialog.Cancel asChild><button className="ui-button">Cancel</button></AlertDialog.Cancel>
            <AlertDialog.Action asChild><button onClick={onConfirm} className={confirmVariant === "danger" ? "ui-button ui-button-danger" : "ui-button ui-button-primary"}>{confirmLabel}</button></AlertDialog.Action>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}
