/**
 * The finding-class visual language (invariant I1, I8; TASK.md T-107).
 *
 * The rules this file exists to enforce, and `findingClass.test.ts` asserts:
 *  - GROVER_AFFECTED never shares a colour or severity band with QUANTUM_VULNERABLE.
 *    Redlining AES-128 as "migrate now" is the error a domain reviewer catches first.
 *  - CLASSICAL_WEAK gets its own treatment and says it is urgent but NOT a quantum issue.
 *  - UNKNOWN is a coverage failure: grey and hatched, never green, never a risk colour.
 */

export type FindingClass =
  | "quantum-vulnerable"
  | "classical-weak"
  | "grover-affected"
  | "quantum-safe"
  | "unknown";

export const FINDING_CLASSES: FindingClass[] = [
  "quantum-vulnerable",
  "classical-weak",
  "grover-affected",
  "quantum-safe",
  "unknown",
];

export interface FindingStyle {
  label: string;
  short: string;
  severity: "critical" | "urgent" | "informational" | "ok" | "coverage-gap";
  badge: string;
  bar: string;
  hatched: boolean;
  copy: string;
}

export const FINDING: Record<FindingClass, FindingStyle> = {
  "quantum-vulnerable": {
    label: "Quantum-vulnerable",
    short: "Quantum-vulnerable",
    severity: "critical",
    badge: "bg-red-500/15 text-red-300 ring-red-500/40",
    bar: "bg-red-500",
    hatched: false,
    copy: "Broken by Shor's algorithm. This is the PQC migration programme.",
  },
  "classical-weak": {
    label: "Classically weak",
    short: "Classically weak",
    severity: "urgent",
    badge: "bg-orange-500/15 text-orange-300 ring-orange-500/40",
    bar: "bg-orange-500",
    hatched: false,
    copy: "Urgent — but not a quantum issue. Broken today, independent of any quantum computer.",
  },
  "grover-affected": {
    label: "Grover-affected",
    short: "Informational",
    severity: "informational",
    badge: "bg-sky-500/15 text-sky-300 ring-sky-500/40",
    bar: "bg-sky-500",
    hatched: false,
    copy: "Informational. Grover halves symmetric strength but does not break it; prefer 256-bit for long-lived data. Not a migrate-now finding.",
  },
  "quantum-safe": {
    label: "Quantum-safe",
    short: "Quantum-safe",
    severity: "ok",
    badge: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40",
    bar: "bg-emerald-500",
    hatched: false,
    copy: "Confirmed. You already did this right.",
  },
  unknown: {
    label: "Unclassified",
    short: "Coverage gap",
    severity: "coverage-gap",
    badge: "bg-slate-500/15 text-slate-300 ring-slate-500/50 hatched",
    bar: "bg-slate-500 hatched",
    hatched: true,
    copy: "We could not classify this. That is a coverage failure, not a risk verdict — and never counted as safe.",
  },
};

export function isFindingClass(value: string): value is FindingClass {
  return (FINDING_CLASSES as string[]).includes(value);
}

export function styleFor(value: string): FindingStyle {
  return isFindingClass(value) ? FINDING[value] : FINDING.unknown;
}

export type Band = "overdue" | "imminent" | "planned" | "not-applicable" | "coverage-gap";

export const BAND: Record<Band, { label: string; badge: string }> = {
  overdue: { label: "Overdue", badge: "bg-red-500/15 text-red-300 ring-red-500/40" },
  imminent: { label: "Imminent", badge: "bg-amber-500/15 text-amber-300 ring-amber-500/40" },
  planned: { label: "Planned", badge: "bg-slate-500/15 text-slate-300 ring-slate-500/40" },
  "not-applicable": { label: "N/A", badge: "bg-slate-800 text-slate-400 ring-slate-700" },
  "coverage-gap": {
    label: "Coverage gap",
    badge: "bg-slate-500/15 text-slate-300 ring-slate-500/50 hatched",
  },
};

export function bandFor(value: string) {
  return BAND[value as Band] ?? BAND["coverage-gap"];
}
