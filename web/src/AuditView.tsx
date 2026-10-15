import { ArrowsClockwiseIcon, SealCheckIcon, ShieldWarningIcon } from "@phosphor-icons/react";
import { useCallback, useEffect, useState } from "react";
import { getAudit, type Result } from "./api";
import { VERDICT_LABEL, VERDICT_TEXT } from "./labels";
import type { AuditResponse } from "./schemas";

type State = { kind: "loading" } | Result<AuditResponse>;

function formatTime(ts: string | null): string {
  if (!ts) return "";
  const date = new Date(ts);
  return Number.isNaN(date.getTime())
    ? ts
    : date.toLocaleTimeString("en-AU", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function AuditView() {
  const [state, setState] = useState<State>({ kind: "loading" });

  const load = useCallback(() => {
    setState({ kind: "loading" });
    void getAudit(50).then(setState);
  }, []);

  useEffect(() => {
    let cancelled = false;
    void getAudit(50).then((result) => {
      if (!cancelled) setState(result);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section aria-label="Audit trail" className="rounded-[var(--radius-panel)] border border-line bg-surface">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-5 py-4">
        <div>
          <h2 className="text-[18px] font-bold">Audit trail</h2>
          <p className="text-[13px] text-muted">
            Every decision is hash-chained. Records hold a short hash of the arguments, never the values.
          </p>
        </div>
        <button
          type="button"
          onClick={load}
          className="inline-flex items-center gap-2 rounded-[var(--radius-control)] border border-line px-3 py-2 hover:bg-sunken"
        >
          <ArrowsClockwiseIcon size={16} aria-hidden />
          Refresh
        </button>
      </header>

      {state.kind === "loading" && (
        <div className="flex animate-pulse flex-col gap-2 p-5" aria-label="Loading audit trail">
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="h-5 rounded bg-sunken" />
          ))}
        </div>
      )}
      {(state.kind === "unreachable" || state.kind === "failed" || state.kind === "rejected") && (
        <p role="alert" className="p-5 text-deny">
          The audit trail couldn't be loaded. Check the firewall API is running, then refresh.
        </p>
      )}
      {state.kind === "ok" && <AuditBody data={state.value} />}
    </section>
  );
}

function AuditBody({ data }: { data: AuditResponse }) {
  const { chain, records } = data;
  return (
    <>
      <div className="flex items-start gap-3 px-5 py-4">
        {chain.ok ? (
          <SealCheckIcon size={22} weight="fill" className="mt-0.5 shrink-0 text-allow" aria-hidden />
        ) : (
          <ShieldWarningIcon size={22} weight="fill" className="mt-0.5 shrink-0 text-deny" aria-hidden />
        )}
        <p>
          {chain.ok ? (
            <>
              <strong className="font-medium">Chain intact.</strong>{" "}
              <span className="text-muted">
                {chain.count} {chain.count === 1 ? "record" : "records"}
                {chain.head && (
                  <>
                    , head <code className="font-mono text-[13px]">{chain.head.slice(0, 12)}</code>
                  </>
                )}
                .
              </span>
            </>
          ) : (
            <>
              <strong className="font-medium text-deny">Chain broken at record {chain.first_bad}.</strong>{" "}
              <span className="text-muted">A record was edited, removed or reordered after it was written.</span>
            </>
          )}
        </p>
      </div>

      {records.length === 0 ? (
        <p className="px-5 pb-6 text-muted">No decisions yet. Evaluate a scenario on the console and it appears here.</p>
      ) : (
        <div className="overflow-x-auto px-5 pb-5">
          <table className="w-full min-w-[640px] text-left text-[13px]">
            <thead className="text-muted">
              <tr>
                <th className="py-2 pr-4 font-medium">Time</th>
                <th className="py-2 pr-4 font-medium">Request</th>
                <th className="py-2 pr-4 font-medium">Tool</th>
                <th className="py-2 pr-4 font-medium">Decision</th>
                <th className="py-2 pr-4 font-medium">Reasons</th>
                <th className="py-2 font-medium">Arguments hash</th>
              </tr>
            </thead>
            <tbody>
              {records.map((r, i) => (
                <tr key={`${r.request_id}-${i}`} className="border-t border-line align-top">
                  <td className="py-2 pr-4 font-mono whitespace-nowrap">{formatTime(r.ts)}</td>
                  <td className="py-2 pr-4 font-mono">{r.request_id}</td>
                  <td className="py-2 pr-4 font-mono">{r.tool}</td>
                  <td className={`py-2 pr-4 font-medium whitespace-nowrap ${r.verdict ? VERDICT_TEXT[r.verdict] : ""}`}>
                    {r.verdict ? VERDICT_LABEL[r.verdict] : ""}
                  </td>
                  <td className="py-2 pr-4 font-mono text-muted">{(r.reasons ?? []).join(", ") || "none"}</td>
                  <td className="py-2 font-mono text-muted">{r.args_sha256}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
