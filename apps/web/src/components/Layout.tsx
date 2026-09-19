import { useQuery } from "@tanstack/react-query";
import { Link, NavLink, Outlet } from "react-router-dom";
import { api } from "@/api/client";
import { useScanId } from "@/hooks";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/", label: "Posture", end: true },
  { to: "/inventory", label: "Inventory" },
  { to: "/mosca", label: "Mosca explorer" },
  { to: "/roadmap", label: "Roadmap" },
  { to: "/scan", label: "New scan" },
  { to: "/agents", label: "Agents" },
  { to: "/history", label: "History" },
];

export function Layout() {
  const meta = useQuery({ queryKey: ["meta"], queryFn: api.meta });
  const scans = useQuery({ queryKey: ["scans"], queryFn: api.scans });
  const { scanId, setScan } = useScanId();

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
