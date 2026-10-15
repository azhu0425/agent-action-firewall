import {
  CodeIcon,
  EnvelopeIcon,
  FileTextIcon,
  PlayIcon,
  RobotIcon,
  UserIcon,
  WrenchIcon,
} from "@phosphor-icons/react";
import { motion, useReducedMotion } from "motion/react";
import { useLayoutEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from "react";
import { evaluate, type Result } from "./api";
import { REASON_TEXT, SOURCE_LABEL, VERDICT_LABEL, VERDICT_TEXT } from "./labels";
import { taintedSpans, type TaintedSpan } from "./provenance";
import { SCENARIOS, type Scenario } from "./scenarios";
import { EvalRequestSchema, type Decision, type EvalRequest } from "./schemas";
import { StatusBanner } from "./StatusBanner";
import { useHealth } from "./useHealth";

type Outcome = { kind: "idle" } | { kind: "loading" } | Result<Decision>;

const SOURCE_ICON: Record<string, ReactNode> = {
  user: <UserIcon size={16} aria-hidden />,
  assistant: <RobotIcon size={16} aria-hidden />,
  retrieved: <EnvelopeIcon size={16} aria-hidden />,
  tool_output: <WrenchIcon size={16} aria-hidden />,
};

export function ConsoleView() {
  const { health } = useHealth();
  const [scenario, setScenario] = useState<Scenario>(SCENARIOS[0]!);
  const [request, setRequest] = useState<EvalRequest>(SCENARIOS[0]!.request);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [draftError, setDraftError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<Outcome>({ kind: "idle" });
  // The request the shown decision was made for, so the evidence never drifts from the verdict.
  const [evaluated, setEvaluated] = useState<EvalRequest | null>(null);
  const sessionRef = useRef<HTMLDivElement>(null);

  function choose(next: Scenario) {
    setScenario(next);
    setRequest(next.request);
    setEditing(false);
    setDraftError(null);
    setOutcome({ kind: "idle" });
    setEvaluated(null);
  }

  function toggleEditor() {
    if (!editing) setDraft(JSON.stringify(request, null, 2));
    setDraftError(null);
    setEditing(!editing);
  }

  async function run() {
    let body = request;
    if (editing) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(draft);
      } catch {
        setDraftError("That isn't valid JSON. Check for a missing comma or quote.");
        return;
      }
      const checked = EvalRequestSchema.safeParse(parsed);
      if (!checked.success) {
        setDraftError("The JSON parses, but it isn't an evaluation request. Keep the scenario's fields.");
        return;
      }
      body = checked.data;
      setRequest(body);
    }
    setDraftError(null);
    setOutcome({ kind: "loading" });
    setEvaluated(body);
    setOutcome(await evaluate(body));
  }

  const decision = outcome.kind === "ok" ? outcome.value : null;
  const shown = evaluated ?? request;
  const spans = useMemo(() => {
    if (!decision) return [];
    const tainted = decision.findings
      .filter((f) => f.reason === "TAINTED_ARGUMENT" && f.argument)
      .map((f) => f.argument!);
    return taintedSpans(shown.messages, shown.call.arguments, tainted);
  }, [decision, shown]);
  const taintedArgs = new Set(spans.map((s) => s.argument));

  return (
    <div className="flex flex-col gap-4">
      <StatusBanner health={health} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[15.5rem_minmax(0,1fr)_minmax(19rem,23rem)]">
        <ScenarioRail current={scenario.id} onChoose={choose} />

        <section
          aria-label="Agent session"
          className="relative rounded-[var(--radius-panel)] border border-line bg-surface"
        >
          <div ref={sessionRef} className="relative px-5 py-4 pl-9">
            <h2 className="text-[18px] font-bold">Session</h2>
            <p className="mb-4 text-[13px] text-muted">What the agent saw, tagged by where it came from.</p>
            <ol className="flex flex-col gap-3">
              {shown.messages.map((message, index) => (
                <li key={index} className="flex gap-3">
                  <span
                    className={`mt-0.5 inline-flex h-6 shrink-0 items-center gap-1.5 rounded-[var(--radius-control)] px-2 text-[13px] ${
                      message.source === "user" ? "bg-sunken text-ink" : "border border-dashed border-muted/60 text-muted"
                    }`}
                  >
                    {SOURCE_ICON[message.source]}
                    {SOURCE_LABEL[message.source]}
                  </span>
                  <p className="min-w-0 whitespace-pre-wrap break-words">
                    {renderWithMarks(message.content, spans.filter((s) => s.messageIndex === index))}
                  </p>
                </li>
              ))}
            </ol>

            <h2 className="mt-6 text-[18px] font-bold">Proposed call</h2>
            <p className="mb-3 text-[13px] text-muted">
              What the agent wants to do next: <code className="font-mono text-ink">{shown.call.tool}</code>{" "}
              as <code className="font-mono text-ink">{shown.agent_role}</code>.
            </p>
            {editing ? (
              <div className="flex flex-col gap-2">
                <label htmlFor="request-json" className="text-[13px] font-medium">
                  Request JSON
                </label>
                <textarea
                  id="request-json"
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  spellCheck={false}
                  rows={18}
                  className="w-full rounded-[var(--radius-control)] border border-line bg-sunken p-3 font-mono text-[13px] leading-relaxed text-ink"
                />
                {draftError && (
                  <p role="alert" className="text-[13px] text-deny">
                    {draftError}
                  </p>
                )}
              </div>
            ) : (
              <dl className="grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-4 gap-y-1.5">
                {Object.entries(shown.call.arguments).map(([name, value]) => (
                  <div key={name} data-arg-row={name} className="contents">
                    <dt className="font-mono text-[13px] text-muted">{name}</dt>
                    <dd
                      className={`font-mono text-[13px] ${
                        taintedArgs.has(name) ? "rounded-sm bg-mark px-1 text-accent" : ""
                      }`}
                      data-arg-value={name}
                    >
                      {JSON.stringify(value)}
                    </dd>
                  </div>
                ))}
              </dl>
            )}
            <ProvenanceLines containerRef={sessionRef} spans={spans} />
          </div>
          <div className="flex flex-wrap items-center gap-2 border-t border-line px-5 py-3">
            <button
              type="button"
              onClick={() => void run()}
              disabled={outcome.kind === "loading"}
              className="inline-flex items-center gap-2 rounded-[var(--radius-control)] bg-accent px-4 py-2 font-medium text-accent-ink transition-transform active:scale-[0.98] disabled:opacity-60"
            >
              <PlayIcon size={16} weight="fill" aria-hidden />
              Evaluate call
            </button>
            <button
              type="button"
              onClick={toggleEditor}
              aria-pressed={editing}
              className="inline-flex items-center gap-2 rounded-[var(--radius-control)] border border-line px-3 py-2 text-ink hover:bg-sunken"
            >
              <CodeIcon size={16} aria-hidden />
              {editing ? "Done editing" : "Edit JSON"}
            </button>
          </div>
        </section>

        <DecisionPanel outcome={outcome} request={shown} provenanceShown={spans.length > 0} />
      </div>
    </div>
  );
}

function ScenarioRail({ current, onChoose }: { current: string; onChoose: (s: Scenario) => void }) {
  return (
    <nav aria-label="Scenarios" className="flex flex-col gap-1">
      <h2 className="px-1 pb-1 text-[13px] font-medium text-muted">Scenarios</h2>
      {SCENARIOS.map((s) => {
        const active = s.id === current;
        return (
          <button
            key={s.id}
            type="button"
            onClick={() => onChoose(s)}
            aria-current={active ? "true" : undefined}
            className={`rounded-[var(--radius-control)] border-l-2 px-3 py-2 text-left transition-colors ${
              active ? "border-accent bg-surface" : "border-transparent hover:bg-surface/60"
            }`}
          >
            <span className="block font-medium leading-snug">{s.title}</span>
            <span className="block text-[13px] leading-snug text-muted">{s.summary}</span>
          </button>
        );
      })}
    </nav>
  );
}

function renderWithMarks(content: string, spans: TaintedSpan[]): ReactNode {
  if (spans.length === 0) return content;
  const ordered = [...spans].sort((a, b) => a.start - b.start);
  const parts: ReactNode[] = [];
  let cursor = 0;
  ordered.forEach((span, i) => {
    if (span.start < cursor) return; // two arguments matched the same characters
    parts.push(content.slice(cursor, span.start));
    parts.push(
      <mark
        key={i}
        data-testid="provenance-mark"
        data-mark-arg={span.argument}
        className="rounded-sm bg-mark px-0.5 text-accent underline decoration-accent decoration-2 underline-offset-2"
      >
        {content.slice(span.start, span.end)}
      </mark>,
    );
    cursor = span.end;
  });
  parts.push(content.slice(cursor));
  return parts;
}

// Draws one line per tainted argument, from its value in the proposed call back up to where
// that value first appeared in untrusted content. Display only; the verdict is the API's.
function ProvenanceLines({
  containerRef,
  spans,
}: {
  containerRef: RefObject<HTMLDivElement | null>;
  spans: TaintedSpan[];
}) {
  const reduce = useReducedMotion();
  const [paths, setPaths] = useState<{ arg: string; d: string }[]>([]);

  useLayoutEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const measure = () => {
      const box = container.getBoundingClientRect();
      const next: { arg: string; d: string }[] = [];
      for (const arg of new Set(spans.map((s) => s.argument))) {
        const value = container.querySelector(`[data-arg-value="${arg}"]`);
        const mark = container.querySelector(`[data-mark-arg="${arg}"]`);
        if (!value || !mark) continue;
        const v = value.getBoundingClientRect();
        const m = mark.getBoundingClientRect();
        const gutter = 14;
        const vy = v.top + v.height / 2 - box.top;
        const my = m.top + m.height / 2 - box.top;
        const vx = v.left - box.left - 4;
        const mx = m.left - box.left - 2;
        next.push({
          arg,
          d: `M ${vx} ${vy} C ${gutter} ${vy}, ${gutter} ${vy}, ${gutter} ${vy - 12} L ${gutter} ${my + 12} C ${gutter} ${my}, ${gutter} ${my}, ${mx} ${my}`,
        });
      }
      setPaths(next);
    };
    measure();
    // Re-measure when the panel resizes; without ResizeObserver the first measurement stands.
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(measure);
    observer.observe(container);
    return () => observer.disconnect();
  }, [containerRef, spans]);

  if (paths.length === 0) return null;
  return (
    <svg className="pointer-events-none absolute inset-0 h-full w-full overflow-visible" aria-hidden>
      {paths.map((p, i) => (
        <motion.path
          key={p.arg}
          d={p.d}
          fill="none"
          stroke="var(--accent)"
          strokeWidth={1.5}
          strokeLinecap="round"
          initial={reduce ? false : { pathLength: 0, opacity: 0 }}
          animate={{ pathLength: 1, opacity: 1 }}
          transition={{ duration: 0.7, delay: 0.25 + i * 0.15, ease: [0.16, 1, 0.3, 1] }}
        />
      ))}
    </svg>
  );
}

function formatAmount(value: unknown): string | null {
  return typeof value === "number" ? `$${value.toLocaleString("en-AU")}` : null;
}

function consequence(request: EvalRequest, decision: Decision): string {
  const verdict = decision.shadow ? "ALLOW" : decision.verdict;
  const { tool, arguments: args } = request.call;
  if (tool === "transfer_funds") {
    const amount = formatAmount(args.amount) ?? "The money";
    if (verdict === "ALLOW") return `${amount} is sent.`;
    if (verdict === "REQUIRE_HUMAN_APPROVAL") return `${amount} waits for a person to approve it. Nothing moves yet.`;
    return `${amount} stays in the customer's account.`;
  }
  if (tool === "send_email") {
    if (verdict === "ALLOW") return "The email is sent.";
    if (verdict === "REQUIRE_HUMAN_APPROVAL") return "The email waits for a person to approve it.";
    return "The email is not sent.";
  }
  if (verdict === "ALLOW") return "The call goes through.";
  if (verdict === "REQUIRE_HUMAN_APPROVAL") return "The call waits for a person to approve it.";
  return "The call is blocked. Nothing changes.";
}

function DecisionPanel({
  outcome,
  request,
  provenanceShown,
}: {
  outcome: Outcome;
  request: EvalRequest;
  provenanceShown: boolean;
}) {
  const reduce = useReducedMotion();
  return (
    <section
      aria-label="Firewall decision"
      aria-live="polite"
      className="rounded-[var(--radius-panel)] border border-line bg-surface px-5 py-4"
    >
      <h2 className="text-[18px] font-bold">Decision</h2>
      {outcome.kind === "idle" && (
        <div className="mt-6 flex flex-col items-start gap-2 text-muted">
          <FileTextIcon size={28} aria-hidden />
          <p>Choose a scenario and evaluate the call. The firewall's decision and its reasons appear here.</p>
        </div>
      )}
      {outcome.kind === "loading" && (
        <div className="mt-4 flex animate-pulse flex-col gap-3" aria-label="Evaluating">
          <div className="h-10 w-40 rounded-[var(--radius-control)] bg-sunken" />
          <div className="h-4 w-full rounded bg-sunken" />
          <div className="h-4 w-3/4 rounded bg-sunken" />
        </div>
      )}
      {outcome.kind === "unreachable" && (
        <p role="alert" className="mt-4 text-deny">
          The firewall API didn't answer. Check it's running, then evaluate again.
        </p>
      )}
      {outcome.kind === "failed" && (
        <p role="alert" className="mt-4 text-deny">
          The firewall returned an unexpected response (HTTP {outcome.status}). Nothing was allowed.
        </p>
      )}
      {outcome.kind === "rejected" && (
        <div role="alert" className="mt-4">
          <p className="font-medium text-deny">The firewall rejected the request as malformed.</p>
          <ul className="mt-2 list-disc pl-5 font-mono text-[13px] text-muted">
            {outcome.problems.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </div>
      )}
      {outcome.kind === "ok" && (
        <div className="mt-3 flex flex-col gap-5">
          <motion.p
            key={outcome.value.request_id}
            data-testid="verdict"
            initial={reduce ? false : { opacity: 0, scale: 1.08 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ type: "spring", stiffness: 260, damping: 22 }}
            className={`origin-left text-[36px] font-bold leading-none tracking-tight ${VERDICT_TEXT[outcome.value.verdict]}`}
          >
            {VERDICT_LABEL[outcome.value.verdict]}
          </motion.p>
          {outcome.value.shadow && outcome.value.would_be && (
            <p className="text-[13px] text-muted">
              Shadow mode: allowed, but enforcement would have said {VERDICT_LABEL[outcome.value.would_be]}.
            </p>
          )}
          <p className="text-[18px] leading-snug">{consequence(request, outcome.value)}</p>

          {outcome.value.reasons.length > 0 && (
            <div>
              <h3 className="mb-2 text-[13px] font-medium text-muted">Why</h3>
              <ul className="flex flex-col gap-2.5">
                {outcome.value.reasons.map((reason) => {
                  const args = outcome.value.findings
                    .filter((f) => f.reason === reason && f.argument)
                    .map((f) => f.argument);
                  return (
                    <li key={reason}>
                      <code className="font-mono text-[13px]">{reason}</code>
                      <p className="text-[15px] leading-snug text-muted">
                        {REASON_TEXT[reason] ?? "See the decision record for details."}
                        {args.length > 0 && <> Argument: {args.join(", ")}.</>}
                      </p>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
          {provenanceShown && (
            <p className="text-[13px] text-muted">
              Highlighted in the session: where the flagged values first appeared.
            </p>
          )}
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 border-t border-line pt-3 text-[13px] text-muted">
            <dt>Request</dt>
            <dd className="font-mono">{outcome.value.request_id}</dd>
            <dt>Policy</dt>
            <dd className="font-mono">{outcome.value.policy_sha256?.slice(0, 12) ?? "none loaded"}</dd>
          </dl>
        </div>
      )}
    </section>
  );
}
