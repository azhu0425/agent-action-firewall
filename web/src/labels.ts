// Plain-language wording for verdicts and reason codes, in one place.
import type { Verdict } from "./schemas";

export const VERDICT_LABEL: Record<Verdict, string> = {
  ALLOW: "Allowed",
  REQUIRE_HUMAN_APPROVAL: "Needs approval",
  DENY: "Denied",
};

export const VERDICT_TEXT: Record<Verdict, string> = {
  ALLOW: "text-allow",
  REQUIRE_HUMAN_APPROVAL: "text-approve",
  DENY: "text-deny",
};

export const REASON_TEXT: Record<string, string> = {
  NOT_ALLOWLISTED: "This agent is not allowed to use this tool.",
  INVALID_ARGUMENT: "The call has a field this tool doesn't accept, or a value in the wrong format.",
  AMOUNT_OVER_HARD_CAP: "The amount is over this agent's hard limit.",
  AMOUNT_OVER_SOFT_CAP: "The amount is over the limit for transfers without a human.",
  NEW_PAYEE: "The customer has never paid this account before.",
  PII_EGRESS: "Account or card details would leave the bank by email.",
  TAINTED_ARGUMENT:
    "This value appears in content the assistant read (an email or tool result) but never in the customer's own words.",
  POLICY_UNLOADED: "No policy is loaded, so the firewall denies everything.",
  NO_RULES: "No rules are configured, so the firewall denies everything.",
  EVALUATOR_ERROR: "The firewall hit an error and denied the call to stay safe.",
};

export const SOURCE_LABEL: Record<string, string> = {
  user: "Customer",
  assistant: "Agent",
  retrieved: "Retrieved",
  tool_output: "Tool output",
};
