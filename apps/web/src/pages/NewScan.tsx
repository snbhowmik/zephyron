import { api, progressSocket } from "@/api/client";
import { Button, Card, CardTitle, ErrorBox, Pill, StubNotice } from "@/components/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

/** FR-601: the target-type selector. `supported` = what the current build can actually run. */
const TARGETS = [
  {
    value: "repository",
    label: "Repository",
    supported: true,
    hint: "github.com/org/repo or a local path",
  },
  { value: "container-image", label: "Container image", supported: false, hint: "" },
  { value: "network-endpoint", label: "Network / TLS endpoint", supported: false, hint: "" },
  { value: "directory-service", label: "Directory service", supported: false, hint: "" },
  { value: "cloud-account", label: "Cloud account", supported: false, hint: "" },
  { value: "host", label: "Host (deployed agent)", supported: false, hint: "" },
  { value: "cbom-upload", label: "External CBOM upload", supported: false, hint: "" },
];

export function NewScan() {
  const [target, setTarget] = useState("repository");
  const [ref, setRef] = useState("github.com/acme/polyglot-payments");
  const [csv, setCsv] = useState("");
  const [scanId, setScanId] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const importSystems = useMutation({ mutationFn: () => api.importSystems(csv, "text/csv") });
  const start = useMutation({
    mutationFn: () => api.startScan({ target_type: target, target_ref: ref }),
    onSuccess: (r) => setScanId(r.scan_id),
  });

  // The server tells us one thing: the scan ended. A slow poll covers a dropped socket.
  const scan = useQuery({
    queryKey: ["scan-status", scanId],
    queryFn: () => api.scan(scanId as string),
    enabled: !!scanId,
    refetchInterval: (q) =>
      q.state.data && ["complete", "partial", "failed"].includes(q.state.data.status)
        ? false
        : 5000,
  });
  useEffect(() => {
    if (!scanId) return;
    const ws = progressSocket(scanId);
    ws.onmessage = () => {
      void queryClient.invalidateQueries({ queryKey: ["scan-status", scanId] });
      void queryClient.invalidateQueries({ queryKey: ["scans"] });
    };
    return () => ws.close();
  }, [scanId, queryClient]);

  const chosen = TARGETS.find((t) => t.value === target);
  const status = scan.data?.status ?? "running";
  const done = ["complete", "partial", "failed"].includes(status);

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <h1 className="text-xl font-semibold">New scan</h1>

      <Card>
        <CardTitle>1 · What are you scanning?</CardTitle>
        <fieldset className="grid gap-2 border-0 p-0 md:grid-cols-2">
          <legend className="sr-only">Target type</legend>
          {TARGETS.map((t) => (
            <button
              key={t.value}
              type="button"
              aria-pressed={target === t.value}
              onClick={() => setTarget(t.value)}
              className={`rounded-md px-3 py-2 text-left text-sm ring-1 ${target === t.value ? "bg-sky-600/20 ring-sky-500" : "bg-slate-800 ring-slate-700"}`}
            >
              {t.label}{" "}
              {!t.supported ? (
                <Pill className="ml-1 bg-slate-700 text-slate-300 ring-slate-500">
                  not in this build
                </Pill>
              ) : null}
            </button>
          ))}
        </fieldset>
        {target === "host" ? (
          <div className="mt-3">
            <StubNotice title="Host scans run through the deployed agent" task="T-101a">
              The agent enrollment flow and its backend (T-073a) are not built. The agent binary
              exists and its collectors are wired; enrollment is the missing piece.
            </StubNotice>
          </div>
        ) : null}
        {chosen && !chosen.supported && target !== "host" ? (
          <p className="mt-3 text-sm text-slate-400">
            The collector for this target exists in the codebase, but this demo build only replays
            recorded repository scans, so it cannot run here.
          </p>
        ) : null}
      </Card>

      <Card>
        <CardTitle>2 · Target</CardTitle>
        <input
          value={ref}
          onChange={(e) => setRef(e.target.value)}
          placeholder={chosen?.hint}
          aria-label="Target"
          className="w-full rounded-md bg-slate-800 px-3 py-2 text-sm ring-1 ring-slate-700"
        />
      </Card>

      <Card>
        <CardTitle hint="optional">3 · Systems (CSV)</CardTitle>
        <textarea
          value={csv}
          onChange={(e) => setCsv(e.target.value)}
          rows={4}
          aria-label="Systems CSV"
          placeholder="id,name,owner,criticality,data_classification,internet_facing,…"
          className="w-full rounded-md bg-slate-800 p-2 font-mono text-xs ring-1 ring-slate-700"
        />
        <div className="mt-2 flex items-center gap-2">
          <Button disabled={!csv || importSystems.isPending} onClick={() => importSystems.mutate()}>
            Import systems
          </Button>
          {importSystems.data ? (
            <span className="text-sm">
              {importSystems.data.imported} imported ·{" "}
              {importSystems.data.issues.filter((i) => i.severity === "error").length} error(s)
            </span>
          ) : null}
        </div>
        {importSystems.data?.issues.map((i) => (
          <div
            key={`${i.row}-${i.field}-${i.message}`}
            className={`mt-1 text-xs ${i.severity === "error" ? "text-red-300" : "text-slate-400"}`}
          >
            row {i.row} · {i.field ?? "file"}: {i.message}
          </div>
        ))}
        {importSystems.error ? <ErrorBox error={importSystems.error} /> : null}
      </Card>

      <div className="flex items-center gap-3">
        <Button
          variant="primary"
          disabled={!chosen?.supported || !ref || start.isPending}
          onClick={() => start.mutate()}
        >
          Start scan
        </Button>
        {start.error ? <ErrorBox error={start.error} /> : null}
      </div>

      {scanId ? (
        <Card data-testid="progress">
          <CardTitle hint={scanId.slice(0, 8)}>Scan</CardTitle>
          {!done ? (
            <p className="text-sm text-slate-300">
              Running. Large repositories take minutes; you will be told here when it ends.
            </p>
          ) : (
            <p
              className={status === "failed" ? "text-sm text-red-300" : "text-sm text-emerald-300"}
            >
              Ended: {status}
              {scan.data?.summary?.error ? ` (${String(scan.data.summary.error)})` : ""}
            </p>
          )}
          {done ? (
            <p className="mt-3 text-sm">
              <Link className="text-sky-400 underline" to={`/?scan=${scanId}`}>
                Open the results →
              </Link>
            </p>
          ) : null}
        </Card>
      ) : null}
    </div>
  );
}
