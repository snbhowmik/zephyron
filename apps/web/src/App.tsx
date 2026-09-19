import { Layout } from "@/components/Layout";
import { Agents } from "@/pages/Agents";
import { AssetDetail } from "@/pages/AssetDetail";
import { Dashboard } from "@/pages/Dashboard";
import { History } from "@/pages/History";
import { Inventory } from "@/pages/Inventory";
import { Mosca } from "@/pages/Mosca";
import { NewScan } from "@/pages/NewScan";
import { Roadmap } from "@/pages/Roadmap";
import { Route, Routes } from "react-router-dom";

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="inventory" element={<Inventory />} />
        <Route path="assets/:id" element={<AssetDetail />} />
        <Route path="mosca" element={<Mosca />} />
        <Route path="roadmap" element={<Roadmap />} />
        <Route path="scan" element={<NewScan />} />
        <Route path="agents" element={<Agents />} />
        <Route path="history" element={<History />} />
        <Route path="*" element={<div className="p-6">Not found.</div>} />
      </Route>
    </Routes>
  );
}
