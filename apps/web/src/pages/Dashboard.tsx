import { api, downloadExport } from "@/api/client";
import {
  Card,
  CardTitle,
  ClassBar,
  ErrorBox,
  FindingBadge,
  Loading,
  Pill,
  Stat,
  StubNotice,
} from "@/components/ui";
import { useScanId } from "@/hooks";
import { FINDING_CLASSES, styleFor } from "@/lib/findingClass";
import { assetLevel, bindingConstraint, humaniseBound, outcomeCounts } from "@/lib/summarise";
import { pct } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

export function Dashboard() {
  const { scanId, isLoading } = useScanId();
  const scan = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => api.scan(scanId as string),
    enabled: !!scanId,
  });
  const register = useQuery({
    queryKey: ["register", scanId],
    queryFn: () => api.register(scanId as string),
    enabled: !!scanId,
  });

  if (isLoading) return <Loading what="Loading scans" />;
  if (!scanId)
    return (
      <Card>
        No scans yet.{" "}
        <Link className="text-sky-400 underline" to="/scan">
          Start one.
        </Link>
      </Card>
    );
  if (scan.error) return <ErrorBox error={scan.error} />;
  if (register.error) return <ErrorBox error={register.error} />;
  if (!scan.data || !register.data) return <Loading />;

  const level = assetLevel(register.data.entries);
  const constraint = bindingConstraint(register.data.entries);
  const outcomes = outcomeCounts(register.data.entries);
  const total = level.total;
  const roadmap = register.data.roadmap;

  return (
    <div className="space-y-6">
      {scan.data.status !== "complete" ? (
        <output className="block rounded-md border border-amber-700 bg-amber-950/40 p-3 text-sm text-amber-200">
          This scan is <strong>{scan.data.status}</strong>
          {scan.data.summary.degraded_collectors?.length
            ? ` — degraded collectors: ${scan.data.summary.degraded_collectors.join(", ")}. What follows is a partial inventory.`
            : "."}
        </output>
      ) : null}

      {constraint ? (
        <Card className="border-sky-800 bg-sky-950/30" data-testid="binding-constraint">
          <div className="text-xs uppercase tracking-wide text-sky-300">
            Binding constraint on Z
          </div>
          <p className="mt-1 text-lg">
            {constraint.isDeadline ? (
              <>
                <strong>Compliance, not physics:</strong> Z is set to{" "}
                <strong>{constraint.date}</strong> by <em>{humaniseBound(constraint.boundBy)}</em>
                {constraint.binding ? " (regulator-enforced)" : " (advisory)"} — earlier than the{" "}
                {register.data.policy.z_scenario} CRQC scenario.
              </>
            ) : (
              <>
                Z is set by the <strong>{register.data.policy.z_scenario}</strong> CRQC scenario:{" "}
                <strong>{constraint.date}</strong>. No regulatory deadline binds earlier.
              </>
            )}
          </p>
          <p className="mt-1 text-sm text-slate-300">
            <strong>{constraint.late}</strong> of {constraint.evaluated} scored (asset, system)
            pairs already miss it.{" "}
            <Link className="text-sky-400 underline" to={`/mosca?scan=${scanId}`}>
              Explore the scenarios →
            </Link>
          </p>
        </Card>
      ) : null}

      <div className="grid gap-4 md:grid-cols-4">
        <Stat
          label="Cryptographic assets"
          value={total}
          sub={`${scan.data.summary.claims ?? "?"} claims from ${scan.data.collectors.length} collectors`}
        />
        <Stat
          label="Quantum-vulnerable"
          value={level.byClass["quantum-vulnerable"] ?? 0}
          sub="The PQC migration programme"
        />
        <Stat
          label="Classically weak"
          value={level.byClass["classical-weak"] ?? 0}
          sub="Urgent — but not a quantum issue"
        />
        <Card className="hatched" data-testid="coverage-failures">
          <div className="text-xs uppercase tracking-wide text-slate-300">Coverage failures</div>
          <div className="mt-1 text-3xl font-semibold tabular-nums">{level.coverageFailures}</div>
          <div className="mt-1 text-xs text-slate-300">
            {pct(level.coverageFailures, total)} of the estate could not be classified —{" "}
            {level.coverageCapabilityOnly} of those are dependency-level capability, not observed
            usage. Never counted as safe.
          </div>
        </Card>
      </div>

      <Card>
        <CardTitle hint={`${total} assets · denominator shown`}>Finding classes</CardTitle>
        <ClassBar counts={level.byClass} total={total} />
        <ul className="mt-4 grid gap-3 md:grid-cols-2 lg:grid-cols-5">
          {FINDING_CLASSES.map((c) => (
            <li key={c} className="space-y-1">
              <div className="flex items-center justify-between">
                <FindingBadge value={c} />
                <span className="tabular-nums text-lg">{level.byClass[c] ?? 0}</span>
              </div>
              <p className="text-xs text-slate-400">{styleFor(c).copy}</p>
            </li>
          ))}
        </ul>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardTitle hint="CARAF D4 · per (asset, system) pair">Recommended outcome</CardTitle>
          <table className="w-full text-sm">
            <tbody>
              {Object.entries(outcomes).map(([name, n]) => (
                <tr key={name} className="border-t border-slate-800">
                  <td className="py-1.5 capitalize">{name.replace("-", " ")}</td>
                  <td className="py-1.5 text-right tabular-nums">{n}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2 text-xs text-slate-500">
            “Accept” and “phase out” are first-class outcomes. “No outcome” means inventory-only,
            triage, or a coverage gap.
          </p>
        </Card>

        <Card>
          <CardTitle hint={`policy ${register.data.policy.snapshot_id.slice(0, 12)}`}>
            Collectors
          </CardTitle>
          <ul className="space-y-1.5 text-sm">
            {scan.data.collectors.map((c) => (
              <li key={c.collector} className="flex items-center justify-between">
                <span className="font-mono text-xs">{c.collector}</span>
                <Pill
                  className={
                    c.partial
                      ? "bg-amber-500/15 text-amber-300 ring-amber-500/40"
                      : "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40"
                  }
                >
                  {c.partial ? "partial" : "ok"}
                </Pill>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-slate-500">{register.data.heuristics_notice}</p>
        </Card>
      </div>

      {roadmap ? (
        <Card>
          <CardTitle>Roadmap</CardTitle>
          <p className="text-sm text-slate-300">
            {roadmap.waves.length} waves · <strong>{roadmap.bridges.length}</strong> hybrid-bridge
            cycle(s) · {roadmap.infeasible.length} schedule-infeasible unit(s) ·{" "}
            {roadmap.excluded_trust_anchors} external trust anchors inventoried but never scheduled.{" "}
            <Link className="text-sky-400 underline" to={`/roadmap?scan=${scanId}`}>
              Open the roadmap →
            </Link>
          </p>
        </Card>
      ) : null}

      <Card>
        <CardTitle>Exports</CardTitle>
        <div className="flex flex-wrap gap-2 text-sm">
          <button
            type="button"
            className="rounded-md bg-slate-800 px-3 py-1.5 ring-1 ring-slate-700 hover:bg-slate-700"
            onClick={() => void downloadExport(scanId, "cbom")}
          >
            CBOM · CycloneDX 1.7
          </button>
          <button
            type="button"
            className="rounded-md bg-slate-800 px-3 py-1.5 ring-1 ring-slate-700 hover:bg-slate-700"
            onClick={() => void downloadExport(scanId, "cbom", "1.6")}
          >
            CBOM · CycloneDX 1.6
          </button>
          <button
            type="button"
            className="rounded-md bg-slate-800 px-3 py-1.5 ring-1 ring-slate-700 hover:bg-slate-700"
            onClick={() => void downloadExport(scanId, "risk-register")}
          >
            Crypto Risk Register (JSON)
          </button>
          <button
            type="button"
            className="rounded-md bg-slate-800 px-3 py-1.5 ring-1 ring-slate-700 hover:bg-slate-700"
            onClick={() => void downloadExport(scanId, "sarif")}
          >
            SARIF 2.1.0 (CI)
          </button>
        </div>
        <div className="mt-3">
          <StubNotice title="Executive PDF report" task="T-094">
            Not built. The API answers 501 rather than serving an empty file.
          </StubNotice>
        </div>
      </Card>
    </div>
  );
}
