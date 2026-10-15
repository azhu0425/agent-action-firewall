import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ConsoleView } from "./ConsoleView";
import { SCENARIOS } from "./scenarios";

const DENY = {
  request_id: "demo-attack",
  verdict: "DENY",
  reasons: ["AMOUNT_OVER_HARD_CAP", "NEW_PAYEE", "TAINTED_ARGUMENT"],
  findings: [
    { reason: "AMOUNT_OVER_HARD_CAP", verdict: "DENY", argument: "amount" },
    { reason: "NEW_PAYEE", verdict: "REQUIRE_HUMAN_APPROVAL", argument: null },
    { reason: "TAINTED_ARGUMENT", verdict: "DENY", argument: "bsb" },
    { reason: "TAINTED_ARGUMENT", verdict: "DENY", argument: "account_number" },
  ],
  shadow: false,
  would_be: null,
  policy_sha256: "97c469da",
};

function mockFetch(handlers: Record<string, () => Promise<Response>>): void {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      const key = Object.keys(handlers).find((path) => url.endsWith(path));
      return key ? handlers[key]!() : Promise.reject(new TypeError("unexpected " + url));
    }),
  );
}

const json = (status: number, body: unknown) =>
  Promise.resolve(new Response(JSON.stringify(body), { status }));

afterEach(() => vi.unstubAllGlobals());

describe("ConsoleView", () => {
  it("shows the verdict, its reasons and where the tainted values came from", async () => {
    mockFetch({
      "/api/health": () => json(200, { status: "ok", policy_sha256: "97c469da" }),
      "/api/v1/evaluate": () => json(200, DENY),
    });
    render(<ConsoleView />);

    await userEvent.click(await screen.findByRole("button", { name: "Evaluate call" }));

    expect(await screen.findByTestId("verdict")).toHaveTextContent("Denied");
    expect(screen.getAllByText("TAINTED_ARGUMENT").length).toBeGreaterThan(0);
    expect(screen.getAllByTestId("provenance-mark").length).toBeGreaterThan(0);
  });

  it("drops a reply that arrives after the operator switched scenario", async () => {
    let release: (r: Response) => void = () => {};
    const pending = new Promise<Response>((resolve) => {
      release = resolve;
    });
    mockFetch({
      "/api/health": () => json(200, { status: "ok", policy_sha256: "97c469da" }),
      "/api/v1/evaluate": () => pending,
    });
    render(<ConsoleView />);

    await userEvent.click(await screen.findByRole("button", { name: "Evaluate call" }));
    await userEvent.click(screen.getByRole("button", { name: /Rent to a saved payee/ }));
    release(new Response(JSON.stringify(DENY), { status: 200 }));
    await new Promise((r) => setTimeout(r, 20));

    expect(screen.queryByTestId("verdict")).not.toBeInTheDocument();
  });

  it("keeps JSON edits when the editor is closed before evaluating", async () => {
    const sent: unknown[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/api/health")) return json(200, { status: "ok", policy_sha256: "97c469da" });
        sent.push(JSON.parse(String(init?.body)));
        return json(200, DENY);
      }),
    );
    render(<ConsoleView />);

    await userEvent.click(await screen.findByRole("button", { name: "Edit JSON" }));
    const editor = screen.getByLabelText("Request JSON") as HTMLTextAreaElement;
    const edited = JSON.parse(editor.value) as { call: { arguments: { amount: number } } };
    edited.call.arguments.amount = 4321;
    await userEvent.clear(editor);
    await userEvent.click(editor);
    await userEvent.paste(JSON.stringify(edited));
    await userEvent.click(screen.getByRole("button", { name: "Done editing" }));
    await userEvent.click(screen.getByRole("button", { name: "Evaluate call" }));

    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ call: { arguments: { amount: 4321 } } });
  });

  it("explains fail-closed when the policy is not loaded", async () => {
    mockFetch({
      "/api/health": () => json(503, { status: "degraded", reason: "policy_unloaded" }),
    });
    render(<ConsoleView />);

    expect(await screen.findByRole("status")).toHaveTextContent(/no policy is loaded/i);
  });

  it("says what to do when the API cannot be reached", async () => {
    mockFetch({});
    render(<ConsoleView />);

    expect(await screen.findByRole("alert")).toHaveTextContent(/can't reach the firewall/i);
  });

  it("explains the scenario in plain terms when the verdict and reasons match it", async () => {
    mockFetch({
      "/api/health": () => json(200, { status: "ok", policy_sha256: "97c469da" }),
      "/api/v1/evaluate": () => json(200, DENY),
    });
    render(<ConsoleView />);

    await userEvent.click(await screen.findByRole("button", { name: "Evaluate call" }));

    expect(await screen.findByText(SCENARIOS[0]!.explanation)).toBeInTheDocument();
  });

  it("hides the explanation when the reasons differ from the scenario's", async () => {
    mockFetch({
      "/api/health": () => json(200, { status: "ok", policy_sha256: "97c469da" }),
      "/api/v1/evaluate": () => json(200, { ...DENY, reasons: ["AMOUNT_OVER_HARD_CAP"] }),
    });
    render(<ConsoleView />);

    await userEvent.click(await screen.findByRole("button", { name: "Evaluate call" }));

    expect(await screen.findByTestId("verdict")).toHaveTextContent("Denied");
    expect(screen.queryByText(SCENARIOS[0]!.explanation)).not.toBeInTheDocument();
  });

  it("hides the explanation when the verdict differs from the scenario's", async () => {
    const landlord = SCENARIOS.find((s) => s.id === "landlord")!;
    mockFetch({
      "/api/health": () => json(200, { status: "ok", policy_sha256: "97c469da" }),
      "/api/v1/evaluate": () => json(200, DENY),
    });
    render(<ConsoleView />);

    await userEvent.click(await screen.findByRole("button", { name: /Rent to a saved payee/ }));
    await userEvent.click(screen.getByRole("button", { name: "Evaluate call" }));

    expect(await screen.findByTestId("verdict")).toHaveTextContent("Denied");
    expect(screen.queryByText(landlord.explanation)).not.toBeInTheDocument();
  });

  it("swaps the explanation for an edited note after the request is changed", async () => {
    mockFetch({
      "/api/health": () => json(200, { status: "ok", policy_sha256: "97c469da" }),
      "/api/v1/evaluate": () => json(200, DENY),
    });
    render(<ConsoleView />);

    await userEvent.click(await screen.findByRole("button", { name: "Edit JSON" }));
    const editor = screen.getByLabelText("Request JSON") as HTMLTextAreaElement;
    const edited = JSON.parse(editor.value) as { call: { arguments: { amount: number } } };
    edited.call.arguments.amount = 9900;
    await userEvent.clear(editor);
    await userEvent.click(editor);
    await userEvent.paste(JSON.stringify(edited));
    await userEvent.click(screen.getByRole("button", { name: "Evaluate call" }));

    expect(await screen.findByText(/request edited/i)).toBeInTheDocument();
    expect(screen.queryByText(SCENARIOS[0]!.explanation)).not.toBeInTheDocument();
  });

  it("hides the explanation in shadow mode, where the call was allowed", async () => {
    mockFetch({
      "/api/health": () => json(200, { status: "ok", policy_sha256: "97c469da" }),
      "/api/v1/evaluate": () => json(200, { ...DENY, verdict: "ALLOW", shadow: true, would_be: "DENY" }),
    });
    render(<ConsoleView />);

    await userEvent.click(await screen.findByRole("button", { name: "Evaluate call" }));

    expect(await screen.findByText(/shadow mode/i)).toBeInTheDocument();
    expect(screen.queryByText(SCENARIOS[0]!.explanation)).not.toBeInTheDocument();
  });

  it("keeps the explanation when the editor is opened and closed without changes", async () => {
    mockFetch({
      "/api/health": () => json(200, { status: "ok", policy_sha256: "97c469da" }),
      "/api/v1/evaluate": () => json(200, DENY),
    });
    render(<ConsoleView />);

    await userEvent.click(await screen.findByRole("button", { name: "Edit JSON" }));
    await userEvent.click(screen.getByRole("button", { name: "Done editing" }));
    await userEvent.click(screen.getByRole("button", { name: "Evaluate call" }));

    expect(await screen.findByText(SCENARIOS[0]!.explanation)).toBeInTheDocument();
  });
});
