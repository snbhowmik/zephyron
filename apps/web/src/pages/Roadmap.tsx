import { useQuery } from "@tanstack/react-query";
import cytoscape from "cytoscape";
// @ts-expect-error - cytoscape-dagre ships no type declarations
import dagre from "cytoscape-dagre";
import { useEffect, useRef } from "react";
import { api } from "@/api/client";
import type { RoadmapResponse } from "@/api/types";
import { Card, CardTitle, ErrorBox, Loading, Pill } from "@/components/ui";
import { useScanId } from "@/hooks";

cytoscape.use(dagre);

const WAVE_COLOURS = ["#0ea5e9", "#22c55e", "#eab308", "#a855f7", "#f97316", "#14b8a6"];

function Graph({ data }: { data: RoadmapResponse }) {
  const ref = useRef<HTMLDivElement>(null);
  const bridgeMembers = new Set((data.roadmap?.bridges ?? []).flatMap((b) => b.members));
  useEffect(() => {
    if (!ref.current) return;
    const cy = cytoscape({
      container: ref.current,
      elements: [
        ...data.units.map((u) => ({
          data: {
            id: u.id,
            label: `${u.system_id}\n${u.function}`,
            wave: u.wave ?? 0,
            bridge: bridgeMembers.has(u.id),
          },
        })),
        ...data.edges.map((e, i) => ({
          data: { id: `e${i}`, source: e.from, target: e.to, label: e.kind },
        })),
      ],
      layout: { name: "dagre", rankDir: "LR", nodeSep: 40, rankSep: 90 } as cytoscape.LayoutOptions,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "text-wrap": "wrap",
            "text-valign": "center",
            color: "#e2e8f0",
            "font-size": 10,
            shape: "round-rectangle",
            width: 130,
            height: 46,
            "background-color": "#1e293b",
            "border-width": 2,
            "border-color": (n: cytoscape.NodeSingular) =>
              WAVE_COLOURS[(n.data("wave") as number) % WAVE_COLOURS.length] ?? "#0ea5e9",
          },
        },
        {
          selector: "node[?bridge]",
          style: {
            "border-color": "#ef4444",
            "border-style": "dashed",
            "border-width": 3,
            "background-color": "#3b1219",
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": "#64748b",
            "target-arrow-color": "#64748b",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
          },
        },
      ],
    });
    return () => cy.destroy();
  }, [data, bridgeMembers]);
  return (
    <div
      ref={ref}
      className="h-[420px] w-full rounded-md bg-slate-950 ring-1 ring-slate-800"
      data-testid="roadmap-graph"
    />
  );
}

export function Roadmap() {
  const { scanId } = useScanId();
  const road = useQuery({
    queryKey: ["roadmap", scanId],
    queryFn: () => api.roadmap(scanId as string),
    enabled: !!scanId,
  });
  if (!scanId) return <Loading what="Loading scans" />;
  if (road.error) return <ErrorBox error={road.error} />;
  if (!road.data) return <Loading />;
  const doc = road.data.roadmap;
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold">Migration roadmap</h1>
        <p className="text-sm text-slate-400">
          Only assets the operator can change enter the roadmap. Vendor items are dependencies with
          an ETA; regulator-gated items are named blockers; external trust anchors (
          {doc?.excluded_trust_anchors ?? 0}) are inventoried, never scheduled.
        </p>
      </div>
      {road.data.units.length === 0 ? (
        <Card>No migration units — nothing in this scan needs migrating by the operator.</Card>
      ) : (
        <Card>
          <CardTitle hint="tail must finish before head · dashed red = hybrid-bridge cycle">
            Dependency graph
          </CardTitle>
          <Graph data={road.data} />
        </Card>
      )}

      {doc?.bridges.length ? (
        <div className="space-y-3">
          {doc.bridges.map((b) => (
            <Card
              key={b.members.join("+")}
              className="border-red-900 bg-red-950/20"
              data-testid="bridge"
            >
              <div className="flex flex-wrap items-center gap-2">
                <Pill className="bg-red-500/15 text-red-300 ring-red-500/40">
                  Hybrid bridge · {b.variant}
                </Pill>
                <span className="text-sm">{b.members.join("  ⇄  ")}</span>
              </div>
              <p className="mt-1 text-xs text-slate-400">
                A mutual dependency is a finding, not an error: neither side can move first, so both
                run classical and PQC together for a window.
              </p>
              <ol className="mt-2 list-decimal pl-5 text-sm text-slate-300">
                {b.phases.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ol>
              <p className="mt-1 text-xs text-slate-400">Gate: {b.gate}</p>
            </Card>
          ))}
        </div>
      ) : null}

      <Card>
        <CardTitle>Waves</CardTitle>
        <ol className="space-y-2">
          {(doc?.waves ?? []).map((w) => (
            <li key={w.index} className="flex flex-wrap items-center gap-2 text-sm">
              <Pill className="bg-slate-800 text-slate-200 ring-slate-600">Wave {w.index + 1}</Pill>
              <Pill
                className={
                  w.kind === "bridge"
                    ? "bg-red-500/15 text-red-300 ring-red-500/40"
                    : "bg-sky-500/15 text-sky-300 ring-sky-500/40"
                }
              >
                {w.kind}
              </Pill>
              {w.schedule_risk ? (
                <Pill
                  className="bg-amber-500/15 text-amber-300 ring-amber-500/40"
                  title="A gate or vendor has no ETA — no date is rendered rather than inventing one"
                >
                  unbounded — no date
                </Pill>
              ) : null}
              <span className="text-slate-300">{w.units.join(", ")}</span>
            </li>
          ))}
        </ol>
        <table className="mt-4 w-full text-sm">
          <thead className="text-left text-xs uppercase tracking-wide text-slate-400">
            <tr>
              <th className="py-1">Unit</th>
              <th>Wave</th>
              <th>Target quarter</th>
              <th>Feasible</th>
            </tr>
          </thead>
          <tbody>
            {road.data.units.map((u) => (
              <tr key={u.id} className="border-t border-slate-800">
                <td className="py-1.5">{u.id}</td>
                <td>{u.wave === null ? "—" : u.wave + 1}</td>
                <td>{u.target_quarter ?? (u.schedule_risk ? "unbounded" : "—")}</td>
                <td>
                  {u.feasible ? "yes" : <span className="text-red-300">SCHEDULE_INFEASIBLE</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      {doc?.infeasible.length ? (
        <Card>
          <CardTitle>Schedule infeasible</CardTitle>
          {doc.infeasible.map((i) => (
            <div key={i.unit_id} className="mb-3 text-sm">
              <strong>{i.unit_id}</strong> must finish by {i.deadline_quarter} but cannot before{" "}
              {i.earliest_finish_quarter} — {i.deadline_source}
              <ol className="mt-1 list-decimal pl-5 text-xs text-slate-400">
                {i.blocking_chain.map((c) => (
                  <li key={c}>{c}</li>
                ))}
              </ol>
              {i.contended_resource ? (
                <div className="text-xs text-amber-300">Contended: {i.contended_resource}</div>
              ) : null}
            </div>
          ))}
        </Card>
      ) : null}
    </div>
  );
}
