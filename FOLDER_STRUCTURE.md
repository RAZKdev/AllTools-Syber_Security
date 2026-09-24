# AllTools-CyberSec — Initial Folder Structure

```text
alltools-cybersec/
│
├── README.md
├── SKILL.md
├── DESIGN.md
├── AGENTS.md
│
├── frontend/                  # React + TypeScript + Vite UI
│   ├── src/
│   │   ├── app/
│   │   ├── components/
│   │   ├── features/
│   │   ├── pages/
│   │   ├── services/
│   │   ├── hooks/
│   │   ├── lib/
│   │   └── main.tsx
│   └── tests/
│
├── backend/                   # Python + FastAPI application layer
│   ├── app/
│   │   ├── api/
│   │   ├── services/
│   │   ├── repositories/
│   │   ├── models/
│   │   ├── schemas/
│   │   └── main.py
│   └── tests/
│
├── core/                      # Shared, language-neutral domain contracts
│   └── contracts/
│       ├── schemas/           # Canonical JSON Schemas
│       ├── examples/          # Valid sample payloads
│       └── README.md
│
├── security/                  # Security engine
│   ├── rules/
│   │   ├── web/
│   │   ├── tls/
│   │   ├── dns/
│   │   ├── code/
│   │   ├── dependency/
│   │   ├── logs/
│   │   └── configuration/
│   ├── collectors/
│   ├── analyzers/
│   ├── parsers/
│   ├── normalizers/
│   └── executors/
│
├── evidence/                  # Evidence storage abstraction/metadata
├── reports/                   # Report templates/rendering
├── database/                  # Migrations/seeds later
├── tests/                     # Cross-layer/integration fixtures
├── docs/                      # Architecture and operational docs
└── scripts/                   # Safe developer utilities
```

## Layer Ownership

### `frontend/`
Presentation only. It may call backend services and consume canonical contracts.

### `backend/`
Application orchestration, API, persistence, authorization, and business workflows.

### `core/contracts/`
Canonical data shapes and enums shared across the system.

### `security/`
Collectors, parsers, analyzers, and rules. It should not own UI concerns.

### `evidence/`
Artifact storage and evidence lifecycle abstractions.

### `reports/`
Rendering/export logic.

### `database/`
Migration and database lifecycle assets.

## Dependency Direction

```text
frontend ────────┐
                 ▼
           core/contracts
                 ▲
                 │
backend ─────────┘
   │
   └── security
   └── database
   └── evidence
   └── reports
```

Security rules should depend on contracts/domain primitives, not on frontend components.

## Initial Empty-Directory Policy

Empty directories are allowed in this starter scaffold and contain `.gitkeep` only until implementation begins.
