import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "@/api/client";
import type { AssetDetail as Detail, Occurrence, RegisterEntry } from "@/api/types";
import {
  BandBadge,
  Button,
  Card,
  CardTitle,
  ErrorBox,
  FindingBadge,
  Heuristic,
  Loading,
  Pill,
} from "@/components/ui";
import { useScanId } from "@/hooks";
import { styleFor } from "@/lib/findingClass";
import { years } from "@/lib/utils";

function locusText(locus: Occurrence["locus"]): string {
  const l = locus as Record<string, unknown>;
  switch (locus.locus_type) {
    case "source":
      return `${l.repo}:${l.path}:${l.start_line}`;
    case "file":
      return `${l.path}${l.offset ? `:${l.offset}` : ""}`;
    case "network":
      return `${l.host}:${l.port} (${l.protocol})`;
    case "runtime":
      return `${l.process} → ${l.module}`;
    case "cloud":
      return String(l.resource_arn);
    case "container":
      return `${l.path} @ ${String(l.image_digest).slice(0, 19)}`;
    default:
      return JSON.stringify(l);
  }
}

/** The reconciliation view: one asset, N occurrences, N tools (T-104). */
function Reconciliation({ asset }: { asset: Detail }) {
  const byTool = new Map<string, Occurrence[]>();
  for (const o of asset.occurrences)
    byTool.set(o.collector, [...(byTool.get(o.collector) ?? []), o]);
  return (
    <Card data-testid="reconciliation">
      <CardTitle hint="never averaged — every claim is retained">Reconciliation</CardTitle>
      <p className="mb-3 text-lg">
        <strong>1 asset</strong> · <strong>{asset.occurrences.length}</strong> occurrence(s) ·{" "}
        <strong>{byTool.size}</strong> tool(s) · concluded from{" "}
        <Pill className="bg-slate-700 text-slate-100 ring-slate-500">{asset.concluded_tier}</Pill>
      </p>
      <div className="grid gap-3 md:grid-cols-2">
        {[...byTool.entries()].map(([tool, occs]) => (
          <div key={tool} className="rounded-md border border-slate-800 p-3">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs">{tool}</span>
              <Pill className="bg-slate-800 text-slate-300 ring-slate-600">
                {occs[0]?.confidence}
              </Pill>
            </div>
            <ul className="mt-2 space-y-1 text-xs text-slate-300">
              {occs.map((o) => (
                <li key={`${o.locus.locus_type}-${locusText(o.locus)}-${o.raw_ref}`}>
                  <span className="text-slate-500">{o.detection_method} · </span>
                  <span className="font-mono">{locusText(o.locus)}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      {asset.disputed ? (
        <div className="mt-3 rounded-md border border-fuchsia-800 bg-fuchsia-950/30 p-3 text-sm">
          <strong>Disputed.</strong> Two sources disagree about the same occurrence; both claims are
          kept and the asset is scored at its worst plausible reading until an operator rules.
          {asset.disputes.map((d) => (
            <ul key={d.attribute} className="mt-1 list-disc pl-5 text-xs text-slate-300">
              {d.claims.map((c) => (
                <li key={`${c.source_collector}-${c.value}`}>
                  {d.attribute} = <strong>{c.value}</strong> ({c.source_collector})
                </li>
              ))}
              {d.adjudicated_value ? <li>Ruled: {d.adjudicated_value}</li> : null}
            </ul>
          ))}
        </div>
      ) : null}
    </Card>
  );
}

function MoscaTable({ entry }: { entry: RegisterEntry }) {
  const m = entry.mosca;
  if (!m) return <p className="text-sm text-slate-400">{entry.reason}</p>;
  if (m.gap_years === null)
    return (
      <p className="text-sm text-slate-400" data-testid="mosca-not-evaluated">
        Mosca is not evaluated for this asset: {m.note} The zeros that would appear here would mean
        "unknown", not "no exposure", so they are not shown.
      </p>
    );
  return (
    <table className="w-full text-sm">
      <tbody>
        <tr>
          <td className="py-1 text-slate-400">X (confidentiality)</td>
          <td className="text-right tabular-nums">{years(m.x_conf_years)}</td>
        </tr>
        <tr>
          <td className="py-1 text-slate-400">X (integrity)</td>
          <td className="text-right tabular-nums">{years(m.x_integ_years)}</td>
        </tr>
        <tr>
          <td className="py-1 text-slate-400">
            Y (migration time) <Heuristic />
          </td>
          <td className="text-right tabular-nums">{years(m.y_years)}</td>
        </tr>
        <tr>
          <td className="py-1 text-slate-400">Z_effective</td>
          <td className="text-right tabular-nums">
            {years(m.z_years)}{" "}
            <span className="text-slate-500">
              ({entry.z_effective?.date} · {entry.z_effective?.bound_by})
            </span>
          </td>
        </tr>
        <tr className="border-t border-slate-700 font-semibold">
          <td className="py-1">Gap = X + Y − Z</td>
          <td className="text-right tabular-nums">{years(m.gap_years)}</td>
        </tr>
      </tbody>
    </table>
  );
}

function Risk({ entry }: { entry: RegisterEntry }) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <BandBadge value={entry.band} />
        {entry.outcome ? (
          <Pill className="bg-sky-500/15 text-sky-300 ring-sky-500/40">{entry.outcome}</Pill>
        ) : (
          <Pill className="bg-slate-700 text-slate-200 ring-slate-500">no outcome</Pill>
        )}
        {entry.mosca?.mitigation ? (
          <Pill className="bg-slate-800 text-slate-300 ring-slate-600">
            {entry.mosca.mitigation}
          </Pill>
        ) : null}
      </div>
      <p className="text-sm text-slate-200">{entry.reason}</p>
      <MoscaTable entry={entry} />
      {entry.expected_value ? (
        <p className="text-xs text-slate-400">
          EV {entry.expected_value.ev.toFixed(1)} = criticality {entry.expected_value.criticality} ×
          sensitivity {entry.expected_value.sensitivity} × exposure {entry.expected_value.exposure}{" "}
          × gap factor {entry.expected_value.gap_factor.toFixed(2)} <Heuristic />
        </p>
      ) : null}
      <details className="rounded-md border border-slate-800 p-3 text-xs">
        <summary className="cursor-pointer text-slate-300">
          Full computation — inputs, formula and every cited policy value
        </summary>
        {entry.explanations.map((ex) => (
          <div key={ex.name} className="mt-3">
            <div className="font-semibold text-slate-200">
              {ex.name} {ex.heuristic ? <Heuristic /> : null}
            </div>
            <div className="font-mono text-slate-400">{ex.formula}</div>
            <ul className="mt-1 list-disc pl-5 text-slate-300">
              {ex.steps.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ul>
            <ul className="mt-1 space-y-0.5 text-slate-500">
              {ex.policy.map((p) => (
                <li key={p.path}>
                  <span className="font-mono">{p.path}</span> = {JSON.stringify(p.value)} —{" "}
                  {p.basis}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </details>
    </div>
  );
}

function Recommendation({ asset }: { asset: Detail }) {
  const r = asset.recommendation;
  if (!r) return null;
  return (
    <Card>
      <CardTitle hint="status from the primary source, dated">Recommendation</CardTitle>
      <p className="text-sm">{r.reason}</p>
      {r.primary ? (
        <div className="mt-3 rounded-md border border-emerald-800 bg-emerald-950/20 p-3 text-sm">
          <div className="font-semibold">{r.primary.name}</div>
          <div className="text-slate-300">{r.primary.status_text}</div>
          <a
            className="text-xs text-sky-400 underline"
            href={r.primary.source_url}
            target="_blank"
            rel="noreferrer"
          >
            {r.primary.source_url}
          </a>
          <span className="ml-2 text-xs text-slate-500">
            verified {r.primary.verified_on ?? "— UNVERIFIED"}
          </span>
        </div>
      ) : null}
      {r.classical_fix ? <p className="mt-2 text-sm">Classical fix: {r.classical_fix}</p> : null}
      {r.watch?.length ? (
        <p className="mt-2 text-xs text-slate-400">
          Watch (not final standards, <strong>not a compliance claim</strong>): {r.watch.join(", ")}
        </p>
      ) : null}
      {r.hybrid?.length ? (
        <p className="mt-1 text-xs text-slate-400">Hybrid guidance: {r.hybrid.join(", ")}</p>
      ) : null}
      {r.notes?.map((n) => (
        <p key={n} className="mt-1 text-xs text-orange-300">
          {n}
        </p>
      ))}
    </Card>
  );
}

function Triage({ asset }: { asset: Detail }) {
  const qc = useQueryClient();
  const [reason, setReason] = useState("");
  const [author, setAuthor] = useState("");
  const [value, setValue] = useState(asset.disputes[0]?.claims[0]?.value ?? "");
  const suppress = useMutation({
    mutationFn: () => api.suppress(asset.id, { reason, author, days: 30 }),
    onSuccess: () => qc.invalidateQueries(),
  });
  const rule = useMutation({
    mutationFn: () =>
      api.adjudicate(asset.id, {
        attribute: asset.disputes[0]?.attribute ?? "mode",
        value,
        by: author,
        reason,
      }),
    onSuccess: () => qc.invalidateQueries(),
  });
  return (
    <Card>
      <CardTitle hint="audited">Triage</CardTitle>
      <div className="grid gap-2 md:grid-cols-2">
        <input
          placeholder="Your name"
          value={author}
          onChange={(e) => setAuthor(e.target.value)}
          className="rounded-md bg-slate-800 px-3 py-2 text-sm ring-1 ring-slate-700"
        />
        <input
          placeholder="Reason (required)"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          className="rounded-md bg-slate-800 px-3 py-2 text-sm ring-1 ring-slate-700"
        />
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button
          disabled={!reason || !author || suppress.isPending}
          onClick={() => suppress.mutate()}
        >
          Suppress for 30 days
        </Button>
        {asset.disputed ? (
          <>
            <select
              value={value}
              onChange={(e) => setValue(e.target.value)}
              className="rounded-md bg-slate-800 px-2 py-1.5 text-sm ring-1 ring-slate-700"
            >
              {[...new Set(asset.disputes.flatMap((d) => d.claims.map((c) => c.value ?? "")))].map(
                (v) => (
                  <option key={v}>{v}</option>
                ),
              )}
            </select>
            <Button
              variant="primary"
              disabled={!reason || !author || rule.isPending}
              onClick={() => rule.mutate()}
            >
              Rule on the dispute
            </Button>
          </>
        ) : null}
      </div>
      {suppress.error ? (
        <div className="mt-2">
          <ErrorBox error={suppress.error} />
        </div>
      ) : null}
      {rule.error ? (
        <div className="mt-2">
          <ErrorBox error={rule.error} />
        </div>
      ) : null}
      {suppress.isSuccess ? (
        <p className="mt-2 text-xs text-emerald-300">
          Suppressed and recorded in the audit log. The asset stays listed, flagged.
        </p>
      ) : null}
      {rule.isSuccess ? (
        <p className="mt-2 text-xs text-emerald-300">
          Ruling saved; it applies from the next scan.
        </p>
      ) : null}
    </Card>
  );
}

export function AssetDetail() {
  const { id } = useParams();
  const { scanId } = useScanId();
  const asset = useQuery({
    queryKey: ["asset", id],
    queryFn: () => api.asset(id as string),
    enabled: !!id,
  });
  if (asset.error) return <ErrorBox error={asset.error} />;
  if (!asset.data) return <Loading />;
  const a = asset.data;
  const name =
    (a.curve ?? a.parameter_set) ? `${a.family}-${a.curve ?? a.parameter_set}` : a.family;
  return (
    <div className="space-y-5">
      <Link
        className="text-sm text-sky-400 hover:underline"
        to={`/inventory?scan=${scanId ?? a.scan_run_id}`}
      >
        ← Inventory
      </Link>
      <div>
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-semibold">{name}</h1>
          <FindingBadge value={a.finding_class} />
          <Pill className="bg-slate-800 text-slate-300 ring-slate-600">
            {a.function ?? "function unknown"}
          </Pill>
          <Pill className="bg-slate-800 text-slate-300 ring-slate-600" title={a.authority_basis}>
            authority: {a.migration_authority}
          </Pill>
        </div>
        <p className="mt-1 text-sm text-slate-400">{styleFor(a.finding_class).copy}</p>
      </div>
      <Reconciliation asset={a} />
      <div className="grid gap-4 lg:grid-cols-2">
        {a.risk.map((entry) => (
          <Card key={entry.system_id ?? "unassigned"}>
            <CardTitle hint={entry.system_id ? "system" : "unassigned"}>
              {entry.system_id ?? "Unassigned — no system bound"}
            </CardTitle>
            <Risk entry={entry} />
          </Card>
        ))}
      </div>
      <Recommendation asset={a} />
      <Triage asset={a} />
    </div>
  );
}
