import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "@/api/client";
import { BandBadge, Card, CardTitle, ErrorBox, Heuristic, Loading } from "@/components/ui";
import { useScanId } from "@/hooks";
import { BAND, type Band } from "@/lib/findingClass";
import { bindingConstraint, humaniseBound } from "@/lib/summarise";

const SCENARIOS = ["aggressive", "nominal", "conservative"];

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

function Bars({ counts, total }: { counts: Record<string, number>; total: number }) {
  return (
    <ul className="space-y-1.5">
      {(Object.keys(BAND) as Band[]).map((b) => (
        <li key={b} className="flex items-center gap-2 text-sm">
          <span className="w-28">
            <BandBadge value={b} />
          </span>
          <div className="h-2 flex-1 overflow-hidden rounded bg-slate-800">
            <div
              className="h-full bg-sky-500"
              style={{ width: `${((counts[b] ?? 0) / Math.max(total, 1)) * 100}%` }}
            />
          </div>
          <span className="w-10 text-right tabular-nums">{counts[b] ?? 0}</span>
        </li>
      ))}
    </ul>
  );
}

export function Mosca() {
  const { scanId } = useScanId();
  const policy = useQuery({ queryKey: ["policy"], queryFn: api.policy });
  const register = useQuery({
    queryKey: ["register", scanId],
    queryFn: () => api.register(scanId as string),
    enabled: !!scanId,
  });
  const [scenario, setScenario] = useState("nominal");
  const [year, setYear] = useState<number | null>(null);
  const [imminent, setImminent] = useState<number | null>(null);

  const scenarioNode = policy.data?.nodes.find(
    (n) => n.path === `z_scenarios.scenarios.${scenario}`,
  );
  const baseYear = Number(scenarioNode?.fields.crqc_year ?? 2033);
  const shownYear = year ?? baseYear;
  const overrides = useMemo(() => {
    const o: Record<string, unknown> = {};
    if (year !== null && year !== baseYear) o[`z_scenarios.scenarios.${scenario}#crqc_year`] = year;
    if (imminent !== null) o["scoring.mosca.imminent_within_years"] = imminent;
    return o;
  }, [year, imminent, scenario, baseYear]);
  const debounced = useDebounced({ overrides, scenario }, 250);

  const sim = useQuery({
    queryKey: ["simulate", scanId, debounced],
    queryFn: () =>
      api.simulate({
        scan_id: scanId as string,
        overrides: debounced.overrides,
        z_scenario: debounced.scenario,
      }),
    enabled: !!scanId && !!policy.data,
    placeholderData: (p) => p,
  });

  if (!scanId) return <Loading what="Loading scans" />;
  if (policy.error) return <ErrorBox error={policy.error} />;
  if (sim.error) return <ErrorBox error={sim.error} />;
  if (!sim.data || !register.data) return <Loading what="Simulating" />;
  const constraint = bindingConstraint(register.data.entries);
  const total = sim.data.scored;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold">Mosca explorer</h1>
        <p className="text-sm text-slate-400">
          Z is unknowable, so it is a policy input. Move it and every asset is re-scored in place —
          pure recomputation over stored assets, no re-scan, nothing written.
        </p>
      </div>

      <Card>
        <CardTitle>Scenario</CardTitle>
        <div className="flex flex-wrap items-center gap-4">
          <fieldset className="flex gap-1 border-0 p-0">
            <legend className="sr-only">Z scenario</legend>
            {SCENARIOS.map((s) => (
              <button
                key={s}
                type="button"
                aria-pressed={scenario === s}
                onClick={() => {
                  setScenario(s);
                  setYear(null);
                }}
                className={`rounded-md px-3 py-1.5 text-sm ring-1 ${scenario === s ? "bg-sky-600 ring-sky-400" : "bg-slate-800 ring-slate-700"}`}
              >
                {s}
              </button>
            ))}
          </fieldset>
          <label className="flex items-center gap-3 text-sm">
            CRQC year
            <input
              type="range"
              min={2027}
              max={2045}
              value={shownYear}
              onChange={(e) => setYear(Number(e.target.value))}
              aria-label="CRQC year"
            />
            <span className="w-12 tabular-nums font-semibold">{shownYear}</span>
          </label>
          <label className="flex items-center gap-3 text-sm">
            “Imminent” window
            <input
              type="range"
              min={0}
              max={6}
              step={0.5}
              value={imminent ?? 2}
              onChange={(e) => setImminent(Number(e.target.value))}
              aria-label="Imminent window"
            />
            <span className="w-14 tabular-nums">{imminent ?? 2} y</span>
            <Heuristic />
          </label>
        </div>
        <p className="mt-2 text-xs text-slate-500">Scenario basis: {scenarioNode?.basis}</p>
      </Card>

      {constraint ? (
        <Card className="border-sky-800 bg-sky-950/30" data-testid="mosca-constraint">
          <div className="text-xs uppercase tracking-wide text-sky-300">Which constraint binds</div>
          <p className="mt-1">
            {constraint.isDeadline ? (
              <>
                The <strong>{humaniseBound(constraint.boundBy)}</strong> deadline ({constraint.date}
                ) binds Z for the scanned systems, so moving the CRQC scenario changes little for
                them — <strong>the binding constraint is compliance, not physics.</strong>
              </>
            ) : (
              <>The CRQC scenario binds Z ({constraint.date}); moving it moves the result.</>
            )}
          </p>
        </Card>
      ) : null}

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardTitle hint={`policy ${sim.data.baseline_policy_snapshot_id.slice(0, 10)}`}>
            Baseline (as scanned)
          </CardTitle>
          <Bars counts={sim.data.bands.baseline} total={total} />
        </Card>
        <Card>
          <CardTitle
            hint={`${sim.data.changed} of ${total} changed · ${sim.data.scoring_ms.toFixed(0)} ms`}
          >
            Simulated
          </CardTitle>
          <Bars counts={sim.data.bands.candidate} total={total} />
        </Card>
      </div>

      <Card>
        <CardTitle>Top movers</CardTitle>
        {sim.data.top_movers.length === 0 ? (
          <p className="text-sm text-slate-400">
            Nothing moved.{" "}
            {Object.keys(overrides).length === 0
              ? "Change a scenario or slider."
              : "These settings do not change any score."}
          </p>
        ) : (
          <table className="w-full text-sm">
            <tbody>
              {sim.data.top_movers.map((m) => (
                <tr key={`${m.asset_id}-${m.system_id}`} className="border-t border-slate-800">
                  <td className="py-1.5">
                    <Link
                      className="text-sky-300 hover:underline"
                      to={`/assets/${m.asset_id}?scan=${scanId}`}
                    >
                      {m.family}
                    </Link>{" "}
                    <span className="text-slate-500">{m.system_id}</span>
                  </td>
                  <td className="py-1.5">
                    <BandBadge value={m.band.from} /> → <BandBadge value={m.band.to} />
                  </td>
                  <td className="py-1.5 text-right tabular-nums">
                    {m.gap_years.from} → {m.gap_years.to} y
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="mt-3 text-xs text-slate-500">{sim.data.heuristics_notice}</p>
      </Card>
    </div>
  );
}
