import { ApiError, api, getToken, setToken } from "@/api/client";
import { useScanId } from "@/hooks";
import { cn } from "@/lib/utils";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, NavLink, Outlet } from "react-router-dom";

const NAV = [
  { to: "/", label: "Posture", end: true },
  { to: "/inventory", label: "Inventory" },
  { to: "/mosca", label: "Mosca explorer" },
  { to: "/roadmap", label: "Roadmap" },
  { to: "/scan", label: "New scan" },
  { to: "/agents", label: "Agents" },
  { to: "/history", label: "History" },
];

function TokenGate({ onSaved }: { onSaved: () => void }) {
  const [value, setValue] = useState("");
  return (
    <div className="mx-auto max-w-md p-8" data-testid="token-gate">
      <h1 className="mb-2 text-lg font-semibold">Authentication required</h1>
      <p className="mb-4 text-sm text-slate-400">
        This QAVACH API needs its access token. It is kept for this browser tab only and is never
        placed in a URL.
      </p>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          setToken(value.trim());
          onSaved();
        }}
        className="flex gap-2"
      >
        <input
          type="password"
          autoComplete="off"
          aria-label="API token"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          className="flex-1 rounded-md bg-slate-900 px-3 py-1.5 text-sm ring-1 ring-slate-700"
        />
        <button type="submit" className="rounded-md bg-sky-600 px-3 py-1.5 text-sm">
          Continue
        </button>
      </form>
    </div>
  );
}

export function Layout() {
  const queryClient = useQueryClient();
  const meta = useQuery({ queryKey: ["meta"], queryFn: api.meta });
  const scans = useQuery({ queryKey: ["scans"], queryFn: api.scans });
  const { scanId, setScan } = useScanId();

  const needsToken =
    meta.data?.auth === "bearer" &&
    (!getToken() || (scans.error instanceof ApiError && scans.error.status === 401));
  if (needsToken) {
    return (
      <TokenGate
        onSaved={() => {
          void queryClient.invalidateQueries();
        }}
      />
    );
  }

  return (
    <div className="min-h-screen">
      {meta.data?.demo ? (
        <div
          className="bg-amber-500/10 px-4 py-1.5 text-center text-xs text-amber-200"
          data-testid="demo-banner"
        >
          DEMO MODE — {meta.data.demo_note}
        </div>
      ) : null}
      {meta.data?.auth === "none" ? (
        <div className="bg-slate-800 px-4 py-1 text-center text-[11px] text-slate-400">
          This API has no authentication yet. Run it on localhost only.
        </div>
      ) : null}
      <header className="border-b border-slate-800 bg-slate-900/80">
        <div className="mx-auto flex max-w-7xl items-center gap-6 px-4 py-3">
          <Link to="/" className="text-lg font-bold tracking-tight">
            QAVACH
          </Link>
          <nav className="flex flex-wrap gap-1">
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={{ pathname: item.to, search: scanId ? `?scan=${scanId}` : "" }}
                end={item.end}
                className={({ isActive }) =>
                  cn(
                    "rounded-md px-3 py-1.5 text-sm",
                    isActive ? "bg-slate-800 text-white" : "text-slate-400 hover:text-white",
                  )
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-2 text-sm">
            <label htmlFor="scan-select" className="text-slate-400">
              Scan
            </label>
            <select
              id="scan-select"
              className="rounded-md bg-slate-800 px-2 py-1 ring-1 ring-slate-700"
              value={scanId ?? ""}
              onChange={(e) => setScan(e.target.value)}
            >
              {(scans.data ?? []).map((s) => (
                <option key={s.id} value={s.id}>
                  {s.id.slice(0, 8)} · {s.target_ref} · {s.status}
                </option>
              ))}
            </select>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  );
}
