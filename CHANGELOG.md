# Changelog

## 0.2.0 — 2026-10-05

- Added a complete browser workbench for project creation, HAR import, identities, analysis, review, deletion, and report generation.
- Added identity-context records without credentials.
- Added cascading deletion for imported materials and their derived records.
- Added an optional OpenAI-compatible local LLM adapter restricted to numeric loopback addresses.
- Reduced local-model input to structural metadata and enforced evidence-reference ownership before saving hypotheses.
- Added model-run audit records, response security headers, and latest-review report selection.
- Expanded the test suite to 17 checks.

## 0.1.0 — 2026-10-05

- Initial offline vertical slice with versioned scope policy, HAR import, minimization, endpoint catalog, deterministic hypotheses, human review, audit events, and Markdown reports.
