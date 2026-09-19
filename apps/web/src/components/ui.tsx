import { cva, type VariantProps } from "class-variance-authority";
import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from "react";
import { type FindingClass, bandFor, styleFor } from "@/lib/findingClass";
import { cn } from "@/lib/utils";

const button = cva(
  "inline-flex items-center justify-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 disabled:opacity-50",
  {
    variants: {
      variant: {
        primary: "bg-sky-600 text-white hover:bg-sky-500",
        secondary: "bg-slate-800 text-slate-100 hover:bg-slate-700 ring-1 ring-slate-700",
        ghost: "text-slate-300 hover:bg-slate-800",
        danger: "bg-red-700 text-white hover:bg-red-600",
      },
    },
    defaultVariants: { variant: "secondary" },
  },
);

export function Button({
  variant,
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & VariantProps<typeof button>) {
  return <button className={cn(button({ variant }), className)} {...props} />;
}

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("rounded-lg border border-slate-800 bg-slate-900/60 p-4", className)}
      {...props}
    />
  );
}

export function CardTitle({ children, hint }: { children: ReactNode; hint?: ReactNode }) {
  return (
    <div className="mb-3 flex items-baseline justify-between gap-3">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">{children}</h2>
      {hint ? <span className="text-xs text-slate-500">{hint}</span> : null}
    </div>
  );
}

export function Pill({ className, ...props }: HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset",
        className,
      )}
      {...props}
    />
  );
}

export function FindingBadge({ value, title }: { value: string; title?: string }) {
  const style = styleFor(value);
  return (
    <Pill className={style.badge} title={title ?? style.copy} data-finding-class={value}>
      {style.label}
    </Pill>
  );
}

export function BandBadge({ value }: { value: string }) {
  const band = bandFor(value);
  return <Pill className={band.badge}>{band.label}</Pill>;
}

export function Stat({
  label,
  value,
  sub,
  className,
}: { label: string; value: ReactNode; sub?: ReactNode; className?: string }) {
  return (
    <Card className={className}>
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className="mt-1 text-3xl font-semibold tabular-nums">{value}</div>
      {sub ? <div className="mt-1 text-xs text-slate-400">{sub}</div> : null}
    </Card>
  );
}

export function ClassBar({ counts, total }: { counts: Record<string, number>; total: number }) {
  const order: FindingClass[] = [
    "quantum-vulnerable",
    "classical-weak",
    "grover-affected",
    "quantum-safe",
    "unknown",
  ];
  return (
    <div
      className="flex h-3 w-full overflow-hidden rounded-full bg-slate-800"
      role="img"
      aria-label="Assets by finding class"
    >
      {order.map((c) => {
        const n = counts[c] ?? 0;
        return n === 0 ? null : (
          <div
            key={c}
            className={styleFor(c).bar}
            style={{ width: `${(n / Math.max(total, 1)) * 100}%` }}
            title={`${styleFor(c).label}: ${n}`}
          />
        );
      })}
    </div>
  );
}

export function Loading({ what = "Loading" }: { what?: string }) {
  return <div className="p-6 text-sm text-slate-400">{what}…</div>;
}

export function ErrorBox({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div
      role="alert"
      className="rounded-md border border-red-800 bg-red-950/40 p-4 text-sm text-red-200"
    >
      {message}
    </div>
  );
}

/** T-110: an unbuilt capability is a visible, labelled stub. Never hidden, never fake data. */
export function StubNotice({
  title,
  task,
  children,
}: { title: string; task: string; children?: ReactNode }) {
  return (
    <Card className="border-dashed border-slate-600" data-stub={task}>
      <div className="flex items-center gap-2">
        <Pill className="bg-slate-700 text-slate-200 ring-slate-500">Not implemented · {task}</Pill>
        <h3 className="font-semibold">{title}</h3>
      </div>
      <p className="mt-2 text-sm text-slate-400">{children}</p>
    </Card>
  );
}

export function Heuristic({ children = "planning heuristic" }: { children?: ReactNode }) {
  return (
    <span
      className="ml-1 rounded bg-amber-500/10 px-1 text-[10px] uppercase tracking-wide text-amber-300 ring-1 ring-amber-500/30"
      title="An uncalibrated planning heuristic, not a measurement."
    >
      {children}
    </span>
  );
}
