import { useCallback, useEffect, useState } from "react";
import { getHealth, type Result } from "./api";
import type { Health } from "./schemas";

export type HealthState = { kind: "loading" } | Result<Health>;

export function useHealth(): { health: HealthState; refresh: () => void } {
  const [health, setHealth] = useState<HealthState>({ kind: "loading" });

  const refresh = useCallback(() => {
    let cancelled = false;
    void getHealth().then((result) => {
      if (!cancelled) setHealth(result);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => refresh(), [refresh]);

  return { health, refresh };
}
