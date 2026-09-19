import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api } from "@/api/client";

/** The scan every page is looking at: `?scan=` if present, else the newest. */
export function useScanId(): {
  scanId: string | undefined;
  isLoading: boolean;
  setScan: (id: string) => void;
} {
  const [params, setParams] = useSearchParams();
  const scans = useQuery({ queryKey: ["scans"], queryFn: api.scans });
  const fromUrl = params.get("scan");
  const scanId = fromUrl ?? scans.data?.[0]?.id;
  return {
    scanId,
    isLoading: !fromUrl && scans.isLoading,
    setScan: (id) => {
      const next = new URLSearchParams(params);
      next.set("scan", id);
      setParams(next);
    },
  };
}
