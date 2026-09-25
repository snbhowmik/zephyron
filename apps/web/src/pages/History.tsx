import { api } from "@/api/client";
import type { DiffChange, DiffRow, ScanDiff } from "@/api/types";
import { BandBadge, Card, CardTitle, ErrorBox, FindingBadge, Loading, Pill } from "@/components/ui";
import { cn } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

const DIRECTION: Record<DiffChange["direction"], { label: string; className: string }> = {
  worsened: { label: "worse", className: "bg-red-500/15 text-red-300 ring-red-500/40" },
  improved: {
    label: "better",
    className: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40",
  },
  // I8: moving into or out of "unknown" is lost or regained visibility, never an improvement.
  coverage: { label: "coverage", className: "bg-slate-500/15 text-slate-300 ring-slate-500/40" },
  changed: { label: "changed", className: "bg-sky-500/15 text-sky-300 ring-sky-500/40" },
};

function SummaryChip({ label, value, hint }: { label: string; value: number; hint?: string }) {
  return (
    <div className="rounded-md bg-slate-900 px-3 py-2 ring-1 ring-slate-800" title={hint}>
      <div className="text-lg font-semibold tabular-nums">{value}</div>
      <div className="text-[11px] uppercase tracking-wide text-slate-500">{label}</div>
    </div>
  );
}

function RowsTable({ rows, empty }: { rows: DiffRow[]; empty: string }) {
  if (rows.length === 0) return <p className="text-sm text-slate-500">{empty}</p>;
  return (
    <table className="w-full text-sm">
      <tbody>
        {rows.map((r) => (
          <tr key={`${r.bom_ref}|${r.system_id}`} className="border-t border-slate-800">
            <td className="py-1.5 pr-3 font-mono text-xs">{r.label}</td>
            <td className="pr-3 text-slate-400">{r.system_id || "unassigned"}</td>
            <td className="pr-3">
              <FindingBadge value={r.finding_class} />
            </td>
            <td>
              <BandBadge value={r.band} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function DiffView({ diff }: { diff: ScanDiff }) {
  const s = diff.summary;
  return (
    <div className="space-y-4" data-testid="diff">
      {diff.caveats.length > 0 ? (
        <Card className="border-amber-500/40 bg-amber-500/5">
          <CardTitle>Read this before trusting the diff</CardTitle>
          <ul className="list-disc space-y-1 pl-5 text-sm text-amber-100">
            {diff.caveats.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        </Card>
      ) : null}

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-8">
        <SummaryChip label="added" value={s.added} />
        <SummaryChip label="removed" value={s.removed} />
        <SummaryChip label="worse" value={s.worsened} />
        <SummaryChip label="better" value={s.improved} />
        <SummaryChip
          label="coverage"
          value={s.coverage_changes + s.added_coverage_failures}
          hint="Assets that became, or stopped being, unclassified. Not a risk change (I8)."
        />
        <SummaryChip label="new risks" value={s.added_risky} />
        <SummaryChip label="risks gone" value={s.removed_risky} />
        <SummaryChip label="unchanged" value={s.unchanged} />
      </div>

      <Card>
        <CardTitle hint={`${diff.changed.length}`}>Changed</CardTitle>
        {diff.changed.length === 0 ? (
          <p className="text-sm text-slate-500">No asset changed class, band or outcome.</p>
        ) : (
          <table className="w-full text-sm">
            <tbody>
              {diff.changed.map((c) => (
                <tr
                  key={`${c.bom_ref}|${c.system_id}`}
                  className="border-t border-slate-800 align-top"
                >
                  <td className="py-1.5 pr-3">
                    <Pill className={cn(DIRECTION[c.direction].className)}>
                      {DIRECTION[c.direction].label}
                    </Pill>
                  </td>
                  <td className="pr-3 font-mono text-xs">{c.label}</td>
                  <td className="pr-3 text-slate-400">{c.system_id || "unassigned"}</td>
                  <td className="text-xs text-slate-300">
                    {Object.entries(c.fields).map(([field, [from, to]]) => (
                      <div key={field}>
                        {field}: <span className="text-slate-500">{String(from)}</span> →{" "}
                        <span>{String(to)}</span>
                      </div>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardTitle hint={`${diff.added.length}`}>Added</CardTitle>
          <RowsTable rows={diff.added} empty="Nothing new." />
        </Card>
        <Card>
          <CardTitle hint={`${diff.removed.length}`}>Removed</CardTitle>
          <RowsTable rows={diff.removed} empty="Nothing disappeared." />
        </Card>
      </div>
    </div>
  );
}

export function History() {
  const scans = useQuery({ queryKey: ["scans"], queryFn: api.scans });
  const queryClient = useQueryClient();

 const deleteScan = useMutation({
  mutationFn: async (ids: string[]) => {
    await Promise.all(ids.map((id) => api.deleteScan(id)));
  },
  onSuccess: () => {
    setSelectedScans([]);
    queryClient.invalidateQueries({ queryKey: ["scans"] });
  },
});
  const [before, setBefore] = useState<string>("");
  const [after, setAfter] = useState<string>("");
  const [selectedScans, setSelectedScans] = useState<string[]>([]);

  const list = scans.data ?? [];
  const allSelected = list.length > 0 && selectedScans.length === list.length;

const toggleScan = (id: string) => {
  setSelectedScans((current) =>
    current.includes(id) ? current.filter((scanId) => scanId !== id) : [...current, id],
  );
};

const toggleAll = () => {
  setSelectedScans(allSelected ? [] : list.map((scan) => scan.id));
};
  // The API lists newest first: default to comparing the latest scan with the one before it.
  const afterId = after || list[0]?.id || "";
  const beforeId = before || list[1]?.id || "";

  const diff = useQuery({
    queryKey: ["diff", beforeId, afterId],
    queryFn: () => api.diff(beforeId, afterId),
    enabled: Boolean(beforeId && afterId && beforeId !== afterId),
  });

  if (scans.isLoading) return <Loading what="scans" />;
  if (scans.error) return <ErrorBox error={scans.error} />;

  const select = (value: string, set: (v: string) => void, label: string) => (
    <label className="flex items-center gap-2 text-sm text-slate-400">
      {label}
      <select
        className="rounded-md bg-slate-900 px-2 py-1 text-slate-100 ring-1 ring-slate-700"
        value={value}
        onChange={(event) => set(event.target.value)}
      >
        {list.map((s) => (
          <option key={s.id} value={s.id}>
            {s.id} · {s.started.slice(0, 16).replace("T", " ")} · {s.status}
          </option>
        ))}
      </select>
    </label>
  );

  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <h1 className="text-xl font-semibold">Scan history and drift</h1>
      <Card>
  <div className="flex items-center justify-between">
    <CardTitle>{list.length} scan(s)</CardTitle>

    <div className="flex items-center gap-2">
      <button
        type="button"
        onClick={toggleAll}
        className="rounded-md bg-slate-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-slate-700 hover:bg-slate-700"
      >
        {allSelected ? "Deselect All" : "Select All"}
      </button>

      {selectedScans.length > 0 && (
        <button
          type="button"
          disabled={deleteScan.isPending}
          onClick={() => {
            if (
              window.confirm(
                `Delete ${selectedScans.length} selected scan(s)?`,
              )
            ) {
              deleteScan.mutate(selectedScans);
            }
          }}
          className="rounded-md bg-red-500/10 px-3 py-1.5 text-sm text-red-300 ring-1 ring-red-500/30 hover:bg-red-500/20 disabled:opacity-50"
        >
          {deleteScan.isPending
            ? "Deleting..."
            : `Delete Selected (${selectedScans.length})`}
        </button>
      )}
    </div>
  </div>

  <div className="mt-3 space-y-2">
    {list.map((scan) => (
      <div
        key={scan.id}
        className="flex items-center justify-between rounded-md bg-slate-900 p-3 ring-1 ring-slate-800"
      >
        <div className="flex min-w-0 items-center gap-3">
          <input
            type="checkbox"
            checked={selectedScans.includes(scan.id)}
            onChange={() => toggleScan(scan.id)}
            className="h-4 w-4"
          />

          <div className="min-w-0">
            <div className="truncate font-mono text-xs">{scan.id}</div>
            <div className="text-xs text-slate-500">
              {scan.started.slice(0, 16).replace("T", " ")} · {scan.status}
            </div>
          </div>
        </div>
      </div>
    ))}
  </div>

  <div className="mt-4 flex flex-wrap gap-4">
    {select(beforeId, setBefore, "Before")}
    {select(afterId, setAfter, "After")}
  </div>
</Card>

      {list.length < 2 ? (
        <Card>
          <p className="text-sm text-slate-400">
            Drift needs two scans. Run another scan against the same target to compare.
          </p>
        </Card>
      ) : beforeId === afterId ? (
        <p className="text-sm text-slate-500">Pick two different scans.</p>
      ) : diff.isLoading ? (
        <Loading what="diff" />
      ) : diff.error ? (
        <ErrorBox error={diff.error} />
      ) : diff.data ? (
        <DiffView diff={diff.data} />
      ) : null}
    </div>
  );
}
