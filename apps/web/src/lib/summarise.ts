import type { RegisterEntry } from "@/api/types";

export interface BindingConstraint {
  date: string;
  boundBy: string;
  binding: boolean;
  isDeadline: boolean;
  /** (asset, system) entries whose Mosca gap is positive, i.e. already late. */
  late: number;
  evaluated: number;
}

/**
 * The single most useful sentence on the dashboard (ARCH.md §7.3): which
 * constraint actually bound Z_effective — usually a compliance deadline, years
 * before any plausible CRQC — and how many assets already miss it.
 */
export function bindingConstraint(entries: RegisterEntry[]): BindingConstraint | null {
  const scored = entries.filter((e) => e.z_effective !== null);
  if (scored.length === 0) return null;
  const earliest = scored.reduce((a, b) =>
    (a.z_effective?.date ?? "") <= (b.z_effective?.date ?? "") ? a : b,
  );
  const z = earliest.z_effective;
  if (!z) return null;
  const evaluated = scored.filter((e) => e.mosca?.gap_years !== null && e.mosca !== null);
  return {
    date: z.date,
    boundBy: z.bound_by,
    binding: z.binding,
    isDeadline: z.bound_by.startsWith("deadline:"),
    late: evaluated.filter((e) => (e.mosca?.gap_years ?? 0) > 0).length,
    evaluated: evaluated.length,
  };
}

export function outcomeCounts(entries: RegisterEntry[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const e of entries) {
    const key = e.outcome ?? "no outcome";
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}

export function humaniseBound(boundBy: string): string {
  return boundBy.replace(/^(deadline|scenario):/, "").replace(/_/g, " ");
}

export interface AssetLevel {
  total: number;
  byClass: Record<string, number>;
  coverageFailures: number;
  coverageCapabilityOnly: number;
}

/**
 * Counts each *asset* once. The register has one entry per (asset, system) pair,
 * so summing its entries would report an asset scored under two systems twice —
 * a real dashboard bug this function exists to prevent (`54 assets` for a 27-asset
 * scan). Coverage failures are counted the same way.
 */
export function assetLevel(entries: RegisterEntry[]): AssetLevel {
  const seen = new Map<string, RegisterEntry>();
  for (const e of entries) if (!seen.has(e.bom_ref)) seen.set(e.bom_ref, e);
  const byClass: Record<string, number> = {};
  let coverageFailures = 0;
  let coverageCapabilityOnly = 0;
  for (const e of seen.values()) {
    byClass[e.finding_class] = (byClass[e.finding_class] ?? 0) + 1;
    if (e.finding_class === "unknown") {
      coverageFailures += 1;
      if (e.capability_only) coverageCapabilityOnly += 1;
    }
  }
  return { total: seen.size, byClass, coverageFailures, coverageCapabilityOnly };
}
