# Contributing

ScopePilot welcomes small, reviewable changes that improve authorization controls, data minimization, evidence integrity, offline analysis, documentation, or tests.

Before opening a pull request:

1. Use only synthetic fixtures. Never commit a real HAR, cookie, token, target name, unpublished vulnerability, or third-party personal data.
2. Keep target-side execution out of this MVP. The only current network client is restricted to an explicitly configured numeric loopback local-model endpoint. Any other network request, browser automation, payload execution, or remote-reference resolution needs a separate design review and explicit policy enforcement.
3. Preserve the invariant that only a human review can set a finding to `confirmed`.
4. Add focused tests for authorization boundaries, secret handling, evidence ownership, or report gating when those behaviors change.
5. Run `.venv/bin/pytest` and describe observable behavior in the pull request.

For a security vulnerability in ScopePilot itself, follow `SECURITY.md` instead of opening a public issue.
