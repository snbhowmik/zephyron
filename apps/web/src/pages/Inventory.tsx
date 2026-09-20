import { api } from "@/api/client";
import type { AssetListItem } from "@/api/types";
import {
  BandBadge,
  Button,
  Card,
  CardTitle,
  ErrorBox,
  FindingBadge,
  Loading,
  Pill,
} from "@/components/ui";
import { useScanId } from "@/hooks";
import { certificateRole, commonName } from "@/lib/certificate";
import { styleFor } from "@/lib/findingClass";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";

const FACETS: { key: string; label: string; param: string }[] = [
  { key: "finding_class", label: "Finding class", param: "finding_class" },
  { key: "migration_authority", label: "Migration authority", param: "migration_authority" },
  { key: "band", label: "Urgency band", param: "band" },
  { key: "outcome", label: "Outcome", param: "outcome" },
  { key: "system", label: "System", param: "system_id" },
];

function algorithm(a: AssetListItem): string {
  const detail = a.curve ?? a.parameter_set;
  const base = detail ? `${a.family}-${detail}` : a.family;
  // Two certificates can share an algorithm; the role is what tells them apart.
  return a.certificate
    ? `${base} · ${certificateRole(a.certificate)} ${commonName(a.certificate.subject)}`
    : base;
}

export function Inventory() {
  const { scanId } = useScanId();
  const [params, setParams] = useSearchParams();
  const page = Number(params.get("page") ?? "1");
  const query = {
    finding_class: params.get("finding_class") ?? undefined,
    migration_authority: params.get("migration_authority") ?? undefined,
    band: params.get("band") ?? undefined,
    outcome: params.get("outcome") ?? undefined,
    system_id: params.get("system_id") ?? undefined,
    q: params.get("q") ?? undefined,
    page,
    page_size: 25,
  };
  const assets = useQuery({
    queryKey: ["assets", scanId, query],
    queryFn: () => api.assets(scanId as string, query),
    enabled: !!scanId,
    placeholderData: (previous) => previous,
  });

  function setFilter(param: string, value: string | null) {
    const next = new URLSearchParams(params);
    if (value === null || next.get(param) === value) next.delete(param);
    else next.set(param, value);
    next.delete("page");
    setParams(next);
  }

  if (!scanId) return <Loading what="Loading scans" />;
  if (assets.error) return <ErrorBox error={assets.error} />;
  if (!assets.data) return <Loading what="Loading inventory" />;
  const { items, total, facets, page_size } = assets.data;
  const pages = Math.max(1, Math.ceil(total / page_size));

  return (
    <div className="grid gap-6 lg:grid-cols-[260px_1fr]">
      <aside className="space-y-4" aria-label="Filters">
        <input
          type="search"
          placeholder="Search algorithm…"
          defaultValue={params.get("q") ?? ""}
          onKeyDown={(e) => {
            if (e.key === "Enter") setFilter("q", (e.target as HTMLInputElement).value || null);
          }}
          className="w-full rounded-md bg-slate-800 px-3 py-2 text-sm ring-1 ring-slate-700"
        />
        {FACETS.map((facet) => (
          <Card key={facet.key}>
            <CardTitle>{facet.label}</CardTitle>
            <ul className="space-y-1">
              {Object.entries(facets[facet.key] ?? {}).map(([value, count]) => {
                const active = params.get(facet.param) === (value === "unassigned" ? "" : value);
                return (
                  <li key={value}>
                    <button
                      type="button"
                      onClick={() => setFilter(facet.param, value === "unassigned" ? "" : value)}
                      className={cn(
                        "flex w-full items-center justify-between rounded px-2 py-1 text-left text-sm hover:bg-slate-800",
                        active && "bg-slate-800 ring-1 ring-sky-600",
                      )}
                    >
                      <span
                        className={cn(
                          facet.key === "finding_class" && value === "unknown" && "hatched px-1",
                        )}
                      >
                        {facet.key === "finding_class" ? styleFor(value).label : value}
                      </span>
                      <span className="tabular-nums text-slate-400">{count}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </Card>
        ))}
      </aside>

      <section>
        <div className="mb-3 flex items-center justify-between">
          <h1 className="text-lg font-semibold">
            Inventory <span className="text-slate-400">· {total} assets</span>
          </h1>
          <span className="text-xs text-slate-500">
            Band, outcome and system count (asset, system) pairs — one asset can be scored under
            several systems.
          </span>
        </div>
        {Object.keys(facets.system ?? {}).length > 0 &&
        Object.keys(facets.system ?? {}).every((k) => k === "unassigned" || k === "") ? (
          <div
            className="mb-3 rounded-md border border-sky-800 bg-sky-950/30 p-3 text-sm text-sky-100"
            data-testid="no-systems-notice"
          >
            <strong>No system is bound to these assets.</strong> Their finding classes are real, but
            urgency needs business context (criticality, data retention), so every band reads
            &ldquo;Coverage gap&rdquo;. That is a missing input, not an unclassified algorithm.
            Import a systems file under <em>New scan</em> and re-scan to get urgency and a roadmap.
          </div>
        ) : null}
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-sm" data-testid="inventory-table">
            <thead className="bg-slate-900 text-left text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="px-3 py-2">Algorithm</th>
                <th className="px-3 py-2">Class</th>
                <th className="px-3 py-2">Function</th>
                <th className="px-3 py-2">Authority</th>
                <th className="px-3 py-2 text-right">Tools / occ.</th>
                <th className="px-3 py-2">Urgency</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {items.map((a) => (
                <tr key={a.id} className="border-t border-slate-800 hover:bg-slate-900/60">
                  <td className="px-3 py-2">
                    <Link
                      className="font-medium text-sky-300 hover:underline"
                      to={`/assets/${a.id}?scan=${scanId}`}
                    >
                      {algorithm(a)}
                    </Link>
                  </td>
                  <td className="px-3 py-2">
                    <FindingBadge value={a.finding_class} />
                  </td>
                  <td className="px-3 py-2 text-slate-300">
                    {a.function ?? <em className="text-slate-500">unknown</em>}
                  </td>
                  <td className="px-3 py-2 text-slate-300">{a.migration_authority}</td>
                  <td className="px-3 py-2 text-right tabular-nums">{a.occurrences}</td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      {a.scores.map((s) => (
                        <span key={s.system_id ?? "unassigned"} title={s.system_id ?? "unassigned"}>
                          <BandBadge value={s.band} />
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      {a.capability_only ? (
                        <Pill
                          className="bg-slate-700 text-slate-200 ring-slate-500"
                          title="Evidence is dependency-level capability, not observed usage"
                        >
                          capability
                        </Pill>
                      ) : null}
                      {a.disputed ? (
                        <Pill className="bg-fuchsia-500/15 text-fuchsia-300 ring-fuchsia-500/40">
                          disputed
                        </Pill>
                      ) : null}
                      {a.suppressed ? (
                        <Pill className="bg-slate-700 text-slate-300 ring-slate-500">
                          suppressed
                        </Pill>
                      ) : null}
                    </div>
                  </td>
                </tr>
              ))}
              {items.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-3 py-8 text-center text-slate-500">
                    No assets match these filters.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
        <div className="mt-3 flex items-center justify-between text-sm text-slate-400">
          <span>
            Page {page} of {pages}
          </span>
          <div className="flex gap-2">
            <Button
              disabled={page <= 1}
              onClick={() => setParams({ ...Object.fromEntries(params), page: String(page - 1) })}
            >
              Previous
            </Button>
            <Button
              disabled={page >= pages}
              onClick={() => setParams({ ...Object.fromEntries(params), page: String(page + 1) })}
            >
              Next
            </Button>
          </div>
        </div>
      </section>
    </div>
  );
}
