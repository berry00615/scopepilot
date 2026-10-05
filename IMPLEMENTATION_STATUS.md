# Implementation status

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

## Partially implemented

- SP-03: Scope decisions and audit exist; the verified container network-isolation profile is pending.
- SP-04: HAR import is synchronous; persistent job cancellation and restart recovery are pending.
- SP-05: API uploads are closed and raw content is not persisted; manual project deletion and timed cleanup are pending.
- SP-06: Endpoint catalog exists; editable identity-context records are pending.
- SP-09: Evidence-backed finding queue exists; the review UI is pending.
- SP-12: install, unit, workflow and API checks exist; clean-container and prohibited-egress checks are pending.

## Not implemented yet

- JavaScript, Burp XML and OpenAPI importers.
- LLM gateway, provider permissions, budgets and model-output schema.
- Browser workflow for imports, findings and reviews; `/docs` is currently the working interface.
- Evaluation datasets and dashboards.
- Validated Juice Shop, DVWA and WebGoat deployments.
- Real SRC onboarding or any target-side execution.

## Verification evidence

The current suite has 12 passing tests covering scope boundaries, secret minimization, stable pseudonyms, end-to-end workflow, report gating, analysis idempotency and HTTP origin checks. A live smoke run returned HTTP 200 for the home page, health endpoint and OpenAPI document, with 11 API routes registered.
