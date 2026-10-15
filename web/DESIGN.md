# Interception: design notes

Operator console for the Agent Action Firewall. The audience is people who must understand, in
seconds, what the firewall did to an agent's proposed action and why.

## The one memorable thing
**Provenance.** When a call is denied as `TAINTED_ARGUMENT`, a line in the session's left gutter
joins each flagged argument to the message it came from, and the exact characters are
highlighted (spaced, dashed and full-width forms included). Everything else stays quiet.
The highlight is computed client-side by mirroring `firewall/taint.normalise`; it is evidence only.
The verdict always comes from the API.

## Tokens
| Role | Light | Dark |
|---|---|---|
| Ground | `#E9EDF1` | `#0F1720` |
| Surface | `#F7F9FB` | `#16212C` |
| Ink / muted | `#13202B` / `#5A6875` | `#E6ECF1` / `#93A1AE` |
| Accent (only brand colour: focus, primary action, provenance) | `#2747C9` | `#8EA2F5` |
| Verdicts (semantic only) | allow `#1F7A4D`, approval `#8F5A00`, deny `#B42318` | `#4CC38A`, `#E2A336`, `#F0645A` |

- Type: Hanken Grotesk for the interface, JetBrains Mono only for literal values and identifiers.
  Scale 13 / 15 / 18 / 24 / 36. Self-hosted, no CDN.
- Shape: 6px controls, 10px panels. Elevation by tint and a 1px line, never shadows.
- Motion: two moments only (the verdict settling, the provenance line drawing). Both are off under
  `prefers-reduced-motion`.
- Theme follows the system; both modes are tested.

## Rules
- No values in the browser console or storage (ESLint `no-console`; nothing is persisted).
- Scenarios use synthetic data only (`000` BSBs, RFC 2606 domains), per AGENTS.md §2.3.
- Copy names outcomes in plain words ("$9,800 stays in the customer's account"), errors say what
  to do next, and nothing apologises.
