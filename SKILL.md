# SKILL.md — AllTools-CyberSec Engineering Rules

## 1. Purpose

AllTools-CyberSec is a practical defensive security workbench for authorized assessments, local laboratories, and systems the operator is explicitly permitted to inspect.

This file defines engineering rules for human developers and AI coding agents working in the repository.

## 2. Non-Negotiable Rules

1. Inspect before editing.
2. Read `README.md`, `DESIGN.md`, `AGENTS.md` (when present), and relevant contracts before changing code.
3. Never invent implemented functionality.
4. Do not turn planned features into current features.
5. Do not weaken or bypass scope enforcement.
6. All target-based execution must pass through `Scope Guard`.
7. Never expose secrets, credentials, session tokens, or sensitive evidence in cleartext UI/logs/reports.
8. Prefer passive, low-impact, and explicitly authorized checks.
9. Do not build or add malware, credential theft, persistence, stealth/evasion, destructive exploitation, or attack automation.
10. Preserve existing working behavior unless the task explicitly requires a change or a verified defect demands it.
11. Keep changes scoped and avoid unnecessary dependencies.
12. Every security rule must have tests and deterministic fixtures where practical.
13. Distinguish `Observation`, `Finding`, `Risk`, and `Recommendation`.
14. A checker failure is not a vulnerability finding.
15. Never represent `ERROR`, `BLOCKED_OUT_OF_SCOPE`, or `INSUFFICIENT_DATA` as `PASS`.
16. Preserve evidence metadata and integrity information.
17. Update documentation when behavior, contracts, architecture, or commands change.

## 3. Source-of-Truth Hierarchy

When information conflicts, prefer:

1. Actual source code and tests
2. Configuration and package metadata
3. Canonical contracts in `core/contracts`
4. `SKILL.md`
5. `DESIGN.md`
6. `AGENTS.md`
7. Validated documentation
8. Old README text
9. Prompt/context assumptions

If a contract and implementation disagree, stop and reconcile the mismatch rather than silently inventing behavior.

## 4. Architecture Rules

### Core

`core/contracts` is the canonical domain contract layer.

It owns the language-neutral schema for:

- Workspace
- Engagement
- ScopeItem
- Asset
- Assessment
- CheckExecution
- Observation
- Finding
- Evidence
- Reference
- RiskAssessment
- Remediation
- Retest
- Baseline
- DiffResult
- Incident
- IncidentEvent
- IOCRecord
- Playbook
- PlaybookExecution
- AuditLog

Frontend and backend code must consume or conform to these contracts. Do not create competing domain definitions.

### Security engine

Security checks follow:

`Scope Guard → Collector → Normalizer/Parser → Analyzer/Rule → Observation → Finding → Evidence → Risk`

Collectors collect data. Rules interpret data. Risk models prioritize findings. No single module should own all three responsibilities.

### Rule engine

Every rule must have:

- stable ID
- version
- description
- target/input type
- detection logic
- expected result semantics
- severity guidance
- confidence guidance
- remediation guidance
- references
- tests/fixtures

### Evidence

Evidence is metadata plus an artifact reference. Sensitive values must be redacted before UI display or export when necessary.

Evidence integrity should use cryptographic hashing (for example SHA-256) where artifacts are stored.

## 5. Security Result Semantics

A check may produce:

- `PASS`
- `FAIL`
- `WARN`
- `NOT_TESTED`
- `ERROR`
- `BLOCKED_OUT_OF_SCOPE`
- `INSUFFICIENT_DATA`

Only `FAIL` or an equivalent validated security observation may become a vulnerability-style finding.

`ERROR` means the check did not establish a security conclusion.

## 6. Finding Lifecycle

Preferred lifecycle:

`Detected → Needs Review → Confirmed → Remediation → Retest → Resolved`

Other valid outcomes:

- False Positive
- Accepted Risk
- Mitigated
- Reopened / Regression

Do not delete historical finding state when status changes. Keep status history/audit events.

## 7. Risk Rules

Do not reduce risk to a single severity number.

Risk prioritization may consider:

- technical severity
- asset criticality
- exposure
- confidence
- business context
- exploitability/relevance
- remediation context

`CVSS` is a technical vulnerability severity input, not a complete business-risk model.

## 8. Scope Guard Rules

Every target-based execution must record:

- assessment ID
- target
- scope decision
- scope rule/reference
- timestamp

Out-of-scope targets must be blocked by default.

## 9. Testing Rules

Use local fixtures and lab targets for regression tests.

Do not make real internet targets the only source of automated tests.

For every new security rule:

```text
rule implementation
rule unit test
pass fixture
fail fixture
error/edge fixture when relevant
```

Before delivery, run the narrowest relevant checks first, then broader tests/builds.

## 10. Frontend Rules

Before UI changes:

1. Read `DESIGN.md`.
2. Reuse existing primitives and tokens.
3. Preserve information hierarchy.
4. Do not add decorative UI that hides assessment state.
5. Clearly distinguish severity, status, confidence, and execution errors.
6. Verify responsive behavior and keyboard accessibility where relevant.
7. Prefer data-dense but readable security workflows over dashboard decoration.

## 11. Backend Rules

Backend services should:

- validate inputs
- enforce scope
- normalize data
- return typed/validated responses
- protect secrets
- record meaningful audit events
- avoid leaking sensitive implementation details
- fail closed for authorization/scope failures

## 12. Dependency Rules

Before adding a dependency:

- verify it solves a real need
- check license compatibility
- check maintenance status
- consider supply-chain risk
- prefer standard library or existing project dependencies when adequate

## 13. Data Rules

Minimize collected data.

Do not persist secrets unless the product requirement explicitly demands it and a secure storage design exists.

Use stable IDs and timestamps.

Preserve provenance for evidence and observations.

## 14. Report Rules

Reports must distinguish:

- observed fact
- analyst interpretation
- risk assessment
- recommendation
- unresolved uncertainty

Do not produce a vulnerability claim solely because a heuristic fired when evidence is insufficient.

## 15. AI Agent Workflow

Before work:

1. Inspect repository status.
2. Read relevant documentation/contracts.
3. Locate existing implementation.
4. Identify affected boundaries.
5. Make the smallest coherent change.

After work:

1. Run relevant tests.
2. Run build/type checks where applicable.
3. Verify affected UI behavior when applicable.
4. Review diff for unintended changes.
5. Update docs/contracts when needed.
6. Report exactly what changed and what was verified.

## 16. Definition of Done

A change is complete when:

- behavior matches the requested scope
- canonical contracts are respected
- relevant tests pass
- security boundaries remain intact
- documentation is updated where necessary
- no unrelated files were changed
- limitations are stated explicitly
