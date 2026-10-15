import { PlugsIcon, ShieldWarningIcon } from "@phosphor-icons/react";
import type { HealthState } from "./useHealth";

// Shown above the console when the firewall is not in its normal state. Says what is happening
// and what to do, in the interface's voice.
export function StatusBanner({ health }: { health: HealthState }) {
  if (health.kind === "unreachable" || health.kind === "failed") {
    return (
      <div
        role="alert"
        className="flex items-start gap-3 rounded-[var(--radius-panel)] border border-deny/40 bg-surface px-4 py-3"
      >
        <PlugsIcon size={20} className="mt-0.5 shrink-0 text-deny" aria-hidden />
        <p>
          <strong className="font-medium">Can't reach the firewall API.</strong>{" "}
          <span className="text-muted">
            Start it with <code className="font-mono text-[13px]">docker compose up</code>, then
            refresh this page.
          </span>
        </p>
      </div>
    );
  }
  if (health.kind === "ok" && health.value.status === "degraded") {
    return (
      <div
        role="status"
        className="flex items-start gap-3 rounded-[var(--radius-panel)] border border-deny/40 bg-surface px-4 py-3"
      >
        <ShieldWarningIcon size={20} className="mt-0.5 shrink-0 text-deny" aria-hidden />
        <p>
          <strong className="font-medium">No policy is loaded, so every call is denied.</strong>{" "}
          <span className="text-muted">
            This is the firewall failing closed. Fix the policy file and restart to allow
            traffic again.
          </span>
        </p>
      </div>
    );
  }
  return null;
}
