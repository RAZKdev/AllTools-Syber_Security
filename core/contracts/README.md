# Core Contracts

`core/contracts` is the canonical domain contract layer for AllTools-CyberSec.

## Canonical format

JSON Schema is the language-neutral source of truth for serialized domain objects.

Frontend TypeScript types and backend Python models should be generated or validated against these schemas rather than independently redefining the domain.

## Contract groups

- `workspace.schema.json`
- `engagement.schema.json`
- `scope-item.schema.json`
- `asset.schema.json`
- `assessment.schema.json`
- `check-execution.schema.json`
- `observation.schema.json`
- `finding.schema.json`
- `evidence.schema.json`
- `reference.schema.json`
- `risk-assessment.schema.json`
- `remediation.schema.json`
- `retest.schema.json`
- `baseline.schema.json`
- `diff-result.schema.json`
- `incident.schema.json`
- `incident-event.schema.json`
- `ioc-record.schema.json`
- `playbook.schema.json`
- `playbook-execution.schema.json`
- `audit-log.schema.json`

## Contract rules

1. Use stable IDs.
2. Use ISO-8601 timestamps in UTC for persisted event timestamps.
3. Keep status values explicit and enumerable.
4. Do not put secrets into canonical examples.
5. Preserve provenance for observations and evidence.
6. Additive changes are preferred where compatibility permits.
7. Breaking changes require an explicit contract versioning decision.
