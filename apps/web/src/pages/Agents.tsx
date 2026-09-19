import { api } from "@/api/client";
import type { AgentSummary, IssuedToken } from "@/api/types";
import { Button, Card, CardTitle, ErrorBox, Loading, Pill } from "@/components/ui";
import { cn } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

// The agent's closed vocabulary (ARCH.md §3a): the backend refuses anything else.
const COLLECTORS = [
  ["tls.store", "Certificate stores"],
  ["hsm.evidence", "HSM / PKCS#11 evidence"],
  ["artefact.deployed", "Deployed WAR/EAR/JAR"],
  ["ssh.hostkey", "sshd_config"],
] as const;

const ago = (iso: string | null) => {
  if (!iso) return "never";
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 90) return `${Math.round(seconds)}s ago`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min ago`;
  return `${Math.round(seconds / 3600)} h ago`;
};

function IssueToken() {
  const queryClient = useQueryClient();
  const [host, setHost] = useState("");
  const [ttl, setTtl] = useState(60);
  const [issued, setIssued] = useState<IssuedToken | null>(null);
  const issue = useMutation({
    mutationFn: () => api.issueToken({ host: host.trim(), ttl_minutes: ttl }),
    onSuccess: (token) => {
      setIssued(token);
      void queryClient.invalidateQueries({ queryKey: ["agent-tokens"] });
    },
  });

  return (
    <Card>
      <CardTitle hint="single-use · scoped to one host">Enrol a host</CardTitle>
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          issue.mutate();
        }}
      >
        <label className="text-sm text-slate-400">
          Hostname (exactly as the agent will report it)
          <input
            required
            value={host}
            onChange={(event) => setHost(event.target.value)}
            className="mt-1 block w-64 rounded-md bg-slate-900 px-2 py-1 text-slate-100 ring-1 ring-slate-700"
          />
        </label>
        <label className="text-sm text-slate-400">
          Valid for (min)
          <input
            type="number"
            min={1}
            max={1440}
            value={ttl}
            onChange={(event) => setTtl(Number(event.target.value))}
            className="mt-1 block w-24 rounded-md bg-slate-900 px-2 py-1 text-slate-100 ring-1 ring-slate-700"
          />
        </label>
        <Button type="submit" variant="primary" disabled={issue.isPending || !host.trim()}>
          Generate token
        </Button>
      </form>
      {issue.error ? <ErrorBox error={issue.error} /> : null}
      {issued ? (
        <div className="mt-4 space-y-2 rounded-md bg-slate-950 p-3 ring-1 ring-amber-500/40">
          <p className="text-xs text-amber-200">
            Copy this now. It is shown once, stored only as a hash, and cannot enroll a second host.
            Expires {new Date(issued.expires_at).toLocaleString()}.
          </p>
          <pre className="overflow-x-auto text-xs text-slate-200" data-testid="token">
            {issued.token}
          </pre>
          <pre className="overflow-x-auto text-xs text-slate-400">
            {`qavach-agent enroll --backend-url ${window.location.origin} \\
  --token <token above> --ca-bundle <pinned-server-ca.pem> \\
  --credential-out /etc/qavach/agent.json`}
          </pre>
        </div>
      ) : null}
    </Card>
  );
}

function Dispatch({ agent }: { agent: AgentSummary }) {
  const queryClient = useQueryClient();
  const [paths, setPaths] = useState("");
  const [chosen, setChosen] = useState<string[]>(["tls.store"]);
  const dispatch = useMutation({
    mutationFn: () =>
      api.dispatchAgent(agent.id, {
        paths: paths
          .split("\n")
          .map((p) => p.trim())
          .filter(Boolean),
        collectors: chosen,
      }),
    onSuccess: () => {
      setPaths("");
      void queryClient.invalidateQueries({ queryKey: ["agent", agent.id] });
    },
  });
  return (
    <form
      className="space-y-2"
      onSubmit={(event) => {
        event.preventDefault();
        dispatch.mutate();
      }}
    >
      <textarea
        aria-label="Paths to scan"
        placeholder={"/opt/tomcat/conf\n/etc/ssl"}
        value={paths}
        onChange={(event) => setPaths(event.target.value)}
        rows={3}
        className="w-full rounded-md bg-slate-900 p-2 font-mono text-xs ring-1 ring-slate-700"
      />
      <div className="flex flex-wrap gap-3 text-xs text-slate-300">
        {COLLECTORS.map(([name, label]) => (
          <label key={name} className="flex items-center gap-1">
            <input
              type="checkbox"
              checked={chosen.includes(name)}
              onChange={(event) =>
                setChosen(
                  event.target.checked ? [...chosen, name] : chosen.filter((c) => c !== name),
                )
              }
            />
            {label}
          </label>
        ))}
      </div>
      <Button type="submit" disabled={dispatch.isPending || !paths.trim() || chosen.length === 0}>
        Queue scan
      </Button>
      {dispatch.error ? <ErrorBox error={dispatch.error} /> : null}
      {dispatch.isSuccess ? (
        <p className="text-xs text-emerald-300">Queued. The agent picks it up on its next poll.</p>
      ) : null}
    </form>
  );
}

function AgentPanel({ agent }: { agent: AgentSummary }) {
  const queryClient = useQueryClient();
  const detail = useQuery({
    queryKey: ["agent", agent.id],
    queryFn: () => api.agent(agent.id),
    refetchInterval: 5000,
  });
  const revoke = useMutation({
    mutationFn: () => api.revokeAgent(agent.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["agents"] }),
  });
  return (
    <div className="grid gap-4 border-t border-slate-800 p-3 lg:grid-cols-2">
      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
          Queue a scan
        </h3>
        {agent.status === "active" ? (
          <Dispatch agent={agent} />
        ) : (
          <p className="text-sm text-slate-500">Revoked. It can no longer poll or post.</p>
        )}
        {agent.status === "active" ? (
          <Button
            variant="danger"
            className="mt-3"
            onClick={() => {
              if (window.confirm(`Revoke ${agent.host}? It will need a new token to re-enrol.`))
                revoke.mutate();
            }}
          >
            Revoke agent
          </Button>
        ) : null}
      </div>
      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
          Run history
        </h3>
        {detail.isLoading ? <Loading what="runs" /> : null}
        {detail.data && detail.data.run_history.length === 0 ? (
          <p className="text-sm text-slate-500">No runs yet.</p>
        ) : null}
        <ul className="space-y-1 text-xs">
          {detail.data?.run_history.map((run) => (
            <li key={run.id} className="rounded bg-slate-900 p-2 ring-1 ring-slate-800">
              <span
                className={cn(
                  "mr-2 font-semibold",
                  run.status === "complete" && !run.partial && "text-emerald-300",
                  run.status === "failed" && "text-red-300",
                  (run.partial || run.status === "queued" || run.status === "dispatched") &&
                    "text-amber-300",
                )}
              >
                {run.status}
                {run.partial ? " (partial)" : ""}
              </span>
              <span className="text-slate-400">{run.spec.collectors.join(", ")} · </span>
              <span className="font-mono text-slate-500">{run.spec.paths.join(" ")}</span>
              {run.detail ? <div className="text-red-300">{run.detail}</div> : null}
              {run.scan_run_id ? (
                <div>
                  <a className="text-sky-400 underline" href={`/inventory?scan=${run.scan_run_id}`}>
                    view its inventory
                  </a>
                </div>
              ) : null}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export function Agents() {
  const agents = useQuery({
    queryKey: ["agents"],
    queryFn: api.agents,
    refetchInterval: 5000,
  });
  const tokens = useQuery({ queryKey: ["agent-tokens"], queryFn: api.agentTokens });
  const [open, setOpen] = useState<string | null>(null);

  return (
    <div className="mx-auto max-w-5xl space-y-4">
      <h1 className="text-xl font-semibold">Agents</h1>
      <p className="text-sm text-slate-400">
        A host agent reads keystores and certificate stores the network cannot see. It only ever
        polls this server, and runs a typed scan spec — never a command.
      </p>
      <IssueToken />
      <Card className="p-0">
        <div className="p-4 pb-2">
          <CardTitle hint={`${agents.data?.length ?? 0} enrolled`}>Enrolled agents</CardTitle>
        </div>
        {agents.isLoading ? <Loading what="agents" /> : null}
        {agents.error ? <ErrorBox error={agents.error} /> : null}
        {agents.data && agents.data.length === 0 ? (
          <p className="p-4 pt-0 text-sm text-slate-500">
            None yet. Generate a token above and run <code>qavach-agent enroll</code> on the host.
          </p>
        ) : null}
        {agents.data?.map((agent) => (
          <div key={agent.id}>
            <button
              type="button"
              className="flex w-full items-center gap-4 border-t border-slate-800 px-4 py-2 text-left text-sm hover:bg-slate-800/40"
              onClick={() => setOpen(open === agent.id ? null : agent.id)}
            >
              <Pill
                className={cn(
                  agent.status === "revoked"
                    ? "bg-red-500/15 text-red-300 ring-red-500/40"
                    : agent.online
                      ? "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40"
                      : "bg-slate-500/15 text-slate-300 ring-slate-500/40",
                )}
              >
                {agent.status === "revoked" ? "revoked" : agent.online ? "online" : "offline"}
              </Pill>
              <span className="font-medium">{agent.host}</span>
              <span className="text-slate-500">{agent.os}</span>
              <span className="ml-auto text-xs text-slate-500">
                seen {ago(agent.last_seen)} · {agent.runs ?? 0} run(s) · cert expires{" "}
                {agent.credential_expires.slice(0, 10)}
              </span>
            </button>
            {open === agent.id ? <AgentPanel agent={agent} /> : null}
          </div>
        ))}
      </Card>
      {tokens.data && tokens.data.length > 0 ? (
        <Card>
          <CardTitle>Enrolment tokens</CardTitle>
          <table className="w-full text-xs">
            <tbody>
              {tokens.data.map((t) => (
                <tr key={t.id} className="border-t border-slate-800">
                  <td className="py-1 pr-3">{t.host}</td>
                  <td className="pr-3">{t.state}</td>
                  <td className="text-slate-500">expires {t.expires_at.slice(0, 16)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      ) : null}
    </div>
  );
}
