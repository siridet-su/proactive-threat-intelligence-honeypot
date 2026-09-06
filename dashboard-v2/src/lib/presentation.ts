// Preserve the API's existing classification color meaning at the presentation boundary.
// Do not infer severity or classification from labels, or change the response field.
export function classificationBadgeClass(typeColor: string): string {
  if (typeColor.includes("text-red-400")) return "bg-danger-subtle text-danger border-danger-border";
  if (typeColor.includes("text-amber-400")) return "bg-warning-subtle text-warning border-warning-border";
  return "bg-neutral-subtle text-neutral border-neutral-border";
}
