# AGENTS.md — AllTools-CyberSec Agent Operating Rules

## Before coding

- Read `SKILL.md`.
- Read `DESIGN.md` for frontend/UI work.
- Read `core/contracts/README.md` and affected schemas for domain work.
- Inspect current Git status and existing implementation.

## During coding

- Keep changes scoped.
- Preserve architecture boundaries.
- Never bypass Scope Guard.
- Never commit secrets.
- Do not expose sensitive evidence.
- Do not create duplicate domain models.
- Do not invent APIs or files.

## After coding

- Run relevant tests and type/build checks.
- For UI changes, verify the rendered result when possible.
- Inspect the final diff.
- Update affected documentation/contracts.
- State what was verified and what was not verified.

## Security boundary

This repository is for defensive and authorized security work. Do not add functionality intended for credential theft, persistence, stealth/evasion, malware generation, destructive exploitation, or unauthorized access.
