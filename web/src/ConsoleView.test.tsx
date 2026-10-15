import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ConsoleView } from "./ConsoleView";

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
});
