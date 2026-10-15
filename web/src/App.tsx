import { useEffect, useState } from "react";
import { AuditView } from "./AuditView";
import { ConsoleView } from "./ConsoleView";
import { CorpusView } from "./CorpusView";
import { useHealth } from "./useHealth";

const VIEWS = [
  { id: "console", label: "Console" },
  { id: "audit", label: "Audit trail" },
  { id: "corpus", label: "Corpus" },
] as const;

type ViewId = (typeof VIEWS)[number]["id"];

function viewFromHash(): ViewId {
  const id = window.location.hash.replace("#", "");
  return VIEWS.some((v) => v.id === id) ? (id as ViewId) : "console";
}

export function App() {
  const [view, setView] = useState<ViewId>(viewFromHash);
  const { health } = useHealth();

  useEffect(() => {
    const onHash = () => setView(viewFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const policy =
    health.kind === "ok" && health.value.status === "ok"
      ? { text: `Policy ${health.value.policy_sha256.slice(0, 8)}`, tone: "text-muted" }
      : health.kind === "loading"
        ? { text: "Checking firewall", tone: "text-muted" }
        : { text: "Failing closed", tone: "text-deny" };

  return (
    <div className="mx-auto flex min-h-[100dvh] max-w-[1440px] flex-col gap-4 px-4 py-4 sm:px-6">
      <header className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2">
        <div className="flex items-baseline gap-3">
          <h1 className="text-[24px] font-bold tracking-tight">Interception</h1>
          <p className="hidden text-[13px] text-muted sm:block">Agent action firewall for banking tools</p>
        </div>
        <div className="flex flex-wrap items-center gap-4">
          <span className={`font-mono text-[13px] ${policy.tone}`}>{policy.text}</span>
          <nav aria-label="Views" className="flex rounded-[var(--radius-control)] border border-line bg-surface p-0.5">
            {VIEWS.map((v) => (
              <a
                key={v.id}
                href={`#${v.id}`}
                aria-current={view === v.id ? "page" : undefined}
                className={`rounded-[5px] px-3 py-1.5 text-[13px] font-medium ${
                  view === v.id ? "bg-accent text-accent-ink" : "text-muted hover:text-ink"
                }`}
              >
                {v.label}
              </a>
            ))}
          </nav>
        </div>
      </header>
      <main className="flex-1">
        {view === "console" && <ConsoleView />}
        {view === "audit" && <AuditView />}
        {view === "corpus" && <CorpusView />}
      </main>
    </div>
  );
}
