# Implementation status — v0.2

Updated: 2026-10-05

This file distinguishes implemented behavior from the roadmap in `ScopePilot-项目规划.md`.

## Working vertical slice

- Project creation with a versioned authorization policy.
- Exact HTTP(S) host, port and path-scope decisions; deny rules win; inactive and expired policies fail closed.
- HAR import with a 5 MiB HTTP upload limit and 2,000-entry parser limit.
- Per-entry rejection while retaining only accepted, sanitized evidence.
- Credential removal, email removal and project-scoped stable pseudonyms for object identifiers.
- Endpoint catalog for accepted evidence.
- Deterministic, evidence-backed object-authorization review hypotheses.
- Idempotent analysis runs for the same evidence and rule type.
- Human review records tied to project, policy version, identity, object and stop reason.
- Markdown report export only for human-confirmed findings.
- Audit events for project, policy, import, analysis, review and report actions.
- Loopback-only CLI binding, trusted Host filtering and cross-origin mutation rejection.
- Browser workbench for project creation, HAR upload, identities, analysis, review, deletion and report generation.
- Editable identity-context records containing aliases, roles and ownership notes, with credential-like input rejected.
- Manual artifact deletion cascades through derived endpoints, evidence, findings and reviews while retaining a minimal audit event.
- Optional OpenAI-compatible local LLM gateway restricted to numeric loopback addresses, with redirects and environment proxies disabled.
- Local-model inputs contain structural metadata rather than request or response values; model evidence references are verified before storage.

## Partially implemented

- SP-03: Scope decisions and audit exist; the verified container network-isolation profile is pending.
- SP-04: HAR import is synchronous; persistent job cancellation and restart recovery are pending.
- SP-05: API uploads are closed, raw content is not persisted, and materials can be deleted with their derivatives; project-wide deletion and timed cleanup are pending.
- SP-06: Endpoint catalog and editable identity contexts exist; automated role comparison is pending.
- SP-09: Evidence-backed finding queue and review UI exist; richer evidence inspection is pending.
- SP-12: install, unit, workflow and API checks exist; clean-container and prohibited-egress checks are pending.

## Not implemented yet

- JavaScript, Burp XML and OpenAPI importers.
- External provider permissions and cost budgets; only a loopback local-model gateway is available.
- Evaluation datasets and dashboards.
- Validated Juice Shop, DVWA and WebGoat deployments.
- Real SRC onboarding or any target-side execution.

## Verification evidence

The current suite has 17 passing tests covering scope boundaries, secret minimization, stable pseudonyms, end-to-end workflow, report gating, latest-review selection, analysis idempotency, identity and material deletion, local-model restrictions, evidence-reference validation and HTTP origin checks.
