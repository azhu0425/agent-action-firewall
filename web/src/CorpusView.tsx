import { CheckCircleIcon, PlayIcon, XCircleIcon } from "@phosphor-icons/react";
import { useState } from "react";
import { evaluate } from "./api";
import { CORPUS, type CorpusCase } from "./corpus";
import { VERDICT_LABEL, VERDICT_TEXT } from "./labels";
import type { Verdict } from "./schemas";

type Row = { case: CorpusCase; actual: Verdict | null; reasons: string[]; matched: boolean; error: boolean };

export function CorpusView() {
  const [rows, setRows] = useState<Row[]>([]);
  const [running, setRunning] = useState(false);

  async function run() {
    setRunning(true);
    setRows([]);
    for (const item of CORPUS) {
      const result = await evaluate(item.request);
      const row: Row =
        result.kind === "ok"
          ? {
              case: item,
              actual: result.value.verdict,
              reasons: result.value.reasons,
              matched:
                result.value.verdict === item.expected.decision &&
                item.expected.reasons.every((r) => result.value.reasons.includes(r)),
              error: false,
            }
          : { case: item, actual: null, reasons: [], matched: false, error: true };
      setRows((prev) => [...prev, row]);
    }
    setRunning(false);
  }

  const attacks = rows.filter((r) => r.case.kind === "attack");
  const benign = rows.filter((r) => r.case.kind === "benign");
  const blocked = attacks.filter((r) => r.actual && r.actual !== "ALLOW").length;
  const falseDenies = benign.filter((r) => r.actual === "DENY").length;
  const matched = rows.filter((r) => r.matched).length;
  const done = rows.length === CORPUS.length && !running;

  return (
    <section aria-label="Acceptance corpus" className="rounded-[var(--radius-panel)] border border-line bg-surface">
      <header className="flex flex-wrap items-end justify-between gap-4 border-b border-line px-5 py-4">
        <div className="max-w-[60ch]">
          <h2 className="text-[18px] font-bold">Acceptance corpus</h2>
          <p className="text-[13px] text-muted">
            {CORPUS.length} traces written independently of the rules and approved by a person. Running
            them replays each one against the live firewall and adds {CORPUS.length} records to the audit
            trail.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void run()}
          disabled={running}
          className="inline-flex items-center gap-2 rounded-[var(--radius-control)] bg-accent px-4 py-2 font-medium text-accent-ink transition-transform active:scale-[0.98] disabled:opacity-60"
        >
          <PlayIcon size={16} weight="fill" aria-hidden />
          {running ? `Running ${rows.length} of ${CORPUS.length}` : "Run all traces"}
        </button>
      </header>

      {rows.length === 0 && !running && (
        <p className="px-5 py-6 text-muted">Run the traces to see each expected decision next to the firewall's.</p>
      )}

      {rows.length > 0 && (
        <>
          <dl className="grid grid-cols-1 gap-4 px-5 py-4 sm:grid-cols-3">
            <Metric label="Attacks blocked" value={`${blocked} of ${attacks.length}`} good={blocked === attacks.length} />
            <Metric label="Legitimate calls denied" value={`${falseDenies} of ${benign.length}`} good={falseDenies === 0} />
            <Metric label="Matched expectations" value={`${matched} of ${rows.length}`} good={matched === rows.length} />
          </dl>
          <div className="grid grid-cols-1 gap-6 px-5 pb-5 xl:grid-cols-2">
            <CaseList title="Attacks" rows={attacks} />
            <CaseList title="Legitimate calls" rows={benign} />
          </div>
          {done && (
            <p className="border-t border-line px-5 py-3 text-[13px] text-muted">
              The same gate runs in CI on every pull request, with mutation testing on each rule.
            </p>
          )}
        </>
      )}
    </section>
  );
}

function Metric({ label, value, good }: { label: string; value: string; good: boolean }) {
  return (
    <div>
      <dt className="text-[13px] text-muted">{label}</dt>
      <dd className={`text-[24px] font-bold tabular-nums ${good ? "text-ink" : "text-deny"}`}>{value}</dd>
    </div>
  );
}

function CaseList({ title, rows }: { title: string; rows: Row[] }) {
  return (
    <div>
      <h3 className="mb-2 font-medium">{title}</h3>
      <ul className="flex flex-col">
        {rows.map((row) => (
          <li key={row.case.id} className="flex items-start gap-3 border-t border-line py-2 first:border-t-0">
            {row.matched ? (
              <CheckCircleIcon size={18} weight="fill" className="mt-0.5 shrink-0 text-allow" aria-label="Matched" />
            ) : (
              <XCircleIcon size={18} weight="fill" className="mt-0.5 shrink-0 text-deny" aria-label="Did not match" />
            )}
            <div className="min-w-0 flex-1">
              <p className="leading-snug">{row.case.description}</p>
              <p className="text-[13px] text-muted">
                <span className="font-mono">{row.case.id}</span>
                {" expected "}
                <span className={VERDICT_TEXT[row.case.expected.decision]}>{VERDICT_LABEL[row.case.expected.decision]}</span>
                {", got "}
                {row.actual ? (
                  <span className={VERDICT_TEXT[row.actual]}>{VERDICT_LABEL[row.actual]}</span>
                ) : (
                  <span className="text-deny">no answer</span>
                )}
              </p>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
