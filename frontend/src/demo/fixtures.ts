import {
  Engagement,
  Assessment,
  ScopeItem,
  CheckExecutionRecord,
  Finding,
  Evidence,
  SecurityRuleMetadata,
} from '@/services/api';

export const DEMO_ENGAGEMENT: Engagement = {
  id: 'DEMO-ENG-001',
  workspaceId: 'DEMO-WKS-001',
  name: 'Demo Laboratory Security Assessment',
  description: 'Simulated assessment showcasing defensive security workbench capabilities.',
  assessor: 'Security Analyst (Demo)',
  status: 'ACTIVE',
  rulesOfEngagement: 'Simulated environment only. Zero live network requests generated.',
  createdAt: '2026-10-31T08:00:00Z',
};

export const DEMO_ASSESSMENT: Assessment = {
  id: 'DEMO-ASM-001',
  engagementId: 'DEMO-ENG-001',
  name: 'Demo Full Stack Security Audit',
  type: 'GENERAL',
  status: 'RUNNING',
  startedAt: '2026-10-31T08:15:00Z',
  createdAt: '2026-10-31T08:00:00Z',
};

export const DEMO_SCOPE_ITEMS: ScopeItem[] = [
  {
    id: 'DEMO-SCP-001',
    engagementId: 'DEMO-ENG-001',
    type: 'domain',
    value: 'demo.lab.local',
    environment: 'demo-lab',
    inScope: true,
    notes: 'Authorized simulated web service domain',
  },
  {
    id: 'DEMO-SCP-002',
    engagementId: 'DEMO-ENG-001',
    type: 'cidr',
    value: '192.168.10.0/24',
    environment: 'demo-lab',
    inScope: true,
    notes: 'Authorized simulated lab internal subnet',
  },
  {
    id: 'DEMO-SCP-003',
    engagementId: 'DEMO-ENG-001',
    type: 'domain',
    value: 'prod-database.lab.local',
    environment: 'production',
    inScope: false,
    notes: 'Explicit exclusion: Sensitive database host (Scope Guard test)',
  },
];

export const DEMO_CHECK_EXECUTIONS: CheckExecutionRecord[] = [
  {
    id: 'DEMO-CHK-001',
    assessmentId: 'DEMO-ASM-001',
    ruleId: 'SEC-WEB-001',
    target: 'demo.lab.local',
    scopeDecision: 'ALLOW',
    status: 'FAIL',
    ruleVersion: '1.0.0',
    durationMs: 42,
    executedAt: '2026-10-31T08:20:12Z',
  },
  {
    id: 'DEMO-CHK-002',
    assessmentId: 'DEMO-ASM-001',
    ruleId: 'SEC-TLS-001',
    target: 'demo.lab.local:443',
    scopeDecision: 'ALLOW',
    status: 'WARN',
    ruleVersion: '1.0.0',
    durationMs: 88,
    executedAt: '2026-10-31T08:22:30Z',
  },
  {
    id: 'DEMO-CHK-003',
    assessmentId: 'DEMO-ASM-001',
    ruleId: 'SEC-NET-001',
    target: 'prod-database.lab.local',
    scopeDecision: 'BLOCK',
    status: 'BLOCKED_OUT_OF_SCOPE',
    ruleVersion: '1.0.0',
    durationMs: 2,
    errorCode: 'SCOPE_VIOLATION',
    errorMessage: 'Target explicitly excluded by scope rule DEMO-SCP-003.',
    executedAt: '2026-10-31T08:25:01Z',
  },
  {
    id: 'DEMO-CHK-004',
    assessmentId: 'DEMO-ASM-001',
    ruleId: 'SEC-AUTH-001',
    target: 'DemoPassword!2026',
    scopeDecision: 'ALLOW',
    status: 'PASS',
    ruleVersion: '1.0.0',
    durationMs: 15,
    executedAt: '2026-10-31T08:28:44Z',
  },
];

export const DEMO_FINDINGS: Finding[] = [
  {
    id: 'DEMO-FND-001',
    assessmentId: 'DEMO-ASM-001',
    assetId: 'AST-DEMO-001',
    ruleId: 'SEC-WEB-001',
    title: 'Missing Mandatory Defensive HTTP Security Headers',
    description: 'The target web server does not send Content-Security-Policy, Strict-Transport-Security, and X-Content-Type-Options: nosniff headers.',
    status: 'NEEDS_REVIEW',
    severity: 'medium',
    confidence: 'high',
    cwe: 'CWE-693',
    impact: 'Web browsers connecting to this service cannot enforce anti-framing (clickjacking) or anti-MIME sniffing protections.',
    recommendation: 'Configure the reverse proxy (Nginx/Traefik) to append HSTS, CSP, and X-Content-Type-Options: nosniff response headers.',
    createdAt: '2026-10-31T08:20:12Z',
  },
  {
    id: 'DEMO-FND-002',
    assessmentId: 'DEMO-ASM-001',
    assetId: 'AST-DEMO-002',
    ruleId: 'SEC-TLS-001',
    title: 'Deprecated TLS 1.0/1.1 Protocol Support Detected',
    description: 'Server accepts TLS 1.0 and TLS 1.1 handshakes with outdated cipher suites vulnerable to downgrade attacks.',
    status: 'NEEDS_REVIEW',
    severity: 'high',
    confidence: 'high',
    cwe: 'CWE-326',
    impact: 'Network adversaries can attempt TLS downgrade attacks to intercept or tamper with encrypted sessions.',
    recommendation: 'Disable TLS 1.0 and TLS 1.1 in the TLS terminating gateway; enforce TLS 1.2 minimum and prefer TLS 1.3.',
    createdAt: '2026-10-31T08:22:30Z',
  },
  {
    id: 'DEMO-FND-003',
    assessmentId: 'DEMO-ASM-001',
    assetId: 'AST-DEMO-003',
    ruleId: 'SEC-DNS-001',
    title: 'DNS DMARC Policy in Permissive Mode (p=none)',
    description: 'The DNS DMARC record specifies a policy of p=none, which only generates reports and does not reject spoofed emails.',
    status: 'CONFIRMED',
    severity: 'low',
    confidence: 'high',
    cwe: 'CWE-290',
    impact: 'Attackers can spoof emails originating from the domain name without receiving MTA enforcement rejection.',
    recommendation: 'Transition the DMARC policy from p=none to p=quarantine, then advance to p=reject once mail sources are verified.',
    createdAt: '2026-10-31T08:26:00Z',
  },
];

export const DEMO_EVIDENCE: Evidence[] = [
  {
    id: 'DEMO-EVD-001',
    assessmentId: 'DEMO-ASM-001',
    findingId: 'DEMO-FND-001',
    type: 'http_headers_json',
    source: 'demo.lab.local',
    capturedAt: '2026-10-31T08:20:12Z',
    sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    redacted: false,
    notes: 'HTTP response header snapshot showing missing defensive headers.',
  },
  {
    id: 'DEMO-EVD-002',
    assessmentId: 'DEMO-ASM-001',
    findingId: 'DEMO-FND-002',
    type: 'tls_handshake_json',
    source: 'demo.lab.local:443',
    capturedAt: '2026-10-31T08:22:30Z',
    sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    redacted: false,
    notes: 'TLS handshake cipher negotiation log verifying TLS 1.0 acceptance.',
  },
];

export const DEMO_RULES: SecurityRuleMetadata[] = [
  {
    ruleId: 'SEC-WEB-001',
    title: 'HTTP Defensive Security Headers Audit',
    category: 'Web Security',
    cwe: 'CWE-693',
    description: 'Validates mandatory defensive headers: HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy.',
  },
  {
    ruleId: 'SEC-TLS-001',
    title: 'TLS/SSL Certificate & Cipher Version Inspector',
    category: 'Transport Security',
    cwe: 'CWE-295',
    description: 'Audits certificate validity, SAN/CN matching, expiration grace period, and deprecated protocols.',
  },
  {
    ruleId: 'SEC-DNS-001',
    title: 'DNS Email Security & Anti-Spoofing (SPF/DMARC)',
    category: 'DNS & Email',
    cwe: 'CWE-290',
    description: 'Verifies SPF records and DMARC enforcement policies preventing domain email spoofing.',
  },
  {
    ruleId: 'SEC-WEB-002',
    title: 'Cookie Defensive Security Attributes Audit',
    category: 'Web Security',
    cwe: 'CWE-614',
    description: 'Audits Set-Cookie headers for Secure, HttpOnly, and SameSite attributes to prevent session theft.',
  },
  {
    ruleId: 'SEC-WEB-003',
    title: 'Server Banner & Tech Stack Disclosure Audit',
    category: 'Information Disclosure',
    cwe: 'CWE-200',
    description: 'Detects leaking server tokens, framework headers (X-Powered-By), and version fingerprints.',
  },
  {
    ruleId: 'SEC-WEB-004',
    title: 'CORS Policy & Access-Control Auditor',
    category: 'Web Security',
    cwe: 'CWE-942',
    description: 'Audits CORS headers for dangerous wildcard origins with credentials, null origins, and reflection.',
  },
  {
    ruleId: 'SEC-WEB-005',
    title: 'Sensitive Files & RFC 9116 security.txt Audit',
    category: 'Configuration Hygiene',
    cwe: 'CWE-538',
    description: 'Checks for accidental exposure of .git/.env and validates security.txt disclosure compliance.',
  },
  {
    ruleId: 'SEC-DNS-002',
    title: 'DNS CAA (Certification Authority Authorization) Audit',
    category: 'DNS & Email',
    cwe: 'CWE-295',
    description: 'Verifies DNS CAA records restricting which CAs are permitted to issue certificates.',
  },
  {
    ruleId: 'SEC-NET-001',
    title: 'Authorized Port & Critical Service Exposure Audit',
    category: 'Network Security',
    cwe: 'CWE-284',
    description: 'Probes common sensitive ports (Telnet, FTP, MySQL, Redis, MongoDB, RDP) for unintended exposure.',
  },
  {
    ruleId: 'SEC-CRYPTO-001',
    title: 'Cryptographic Hash Algorithm Strength Analyzer',
    category: 'Cryptography',
    cwe: 'CWE-327',
    description: 'Evaluates hash collision resistance: flags weak MD5/SHA-1 vs strong SHA-256/SHA-512/bcrypt/Argon2.',
  },
  {
    ruleId: 'SEC-AUTH-001',
    title: 'Password Policy & Entropy Compliance Auditor',
    category: 'Identity & Auth',
    cwe: 'CWE-521',
    description: 'Audits password sample complexity, Shannon entropy, and dictionary weaknesses against NIST SP 800-63B.',
  },
];

export const DEMO_REPORT_MARKDOWN = `# Defensive Security Assessment Report — DEMO FIXTURE
> **DEMO DATA — NOT LIVE**: This report was generated from sample fixture data for demonstration purposes.

## 1. Metadata
- **Engagement ID:** \`DEMO-ENG-001\`
- **Assessment ID:** \`DEMO-ASM-001\`
- **Assessment Name:** Demo Full Stack Security Audit
- **Assessor:** Security Analyst (Demo)
- **Status:** COMPLETED (DEMO)

## 2. Executive Summary
This simulated defensive assessment identified **3** finding(s):
- **0** Critical
- **1** High
- **1** Medium
- **1** Low

## 3. Scope Boundary (Demo)
| Rule ID | Type | Value | Policy | Environment |
|---|---|---|---|---|
| \`DEMO-SCP-001\` | domain | \`demo.lab.local\` | **IN SCOPE** | demo-lab |
| \`DEMO-SCP-002\` | cidr | \`192.168.10.0/24\` | **IN SCOPE** | demo-lab |
| \`DEMO-SCP-003\` | domain | \`prod-database.lab.local\` | **EXCLUDED** | production |

## 4. Discovered Findings
### [DEMO-FND-001] Missing Mandatory Defensive HTTP Security Headers
- **Severity:** \`MEDIUM\` | **CWE:** \`CWE-693\` | **Status:** \`NEEDS_REVIEW\`
- **Description:** Target web server lacks HSTS, CSP, and nosniff protection headers.
- **Remediation:** Configure reverse proxy to enforce defensive HTTP headers.

### [DEMO-FND-002] Deprecated TLS 1.0/1.1 Protocol Support Detected
- **Severity:** \`HIGH\` | **CWE:** \`CWE-326\` | **Status:** \`NEEDS_REVIEW\`
- **Description:** Server accepts TLS 1.0/1.1 with outdated ciphers.
- **Remediation:** Enforce TLS 1.2 minimum and prefer TLS 1.3.

### [DEMO-FND-003] DNS DMARC Policy in Permissive Mode (p=none)
- **Severity:** \`LOW\` | **CWE:** \`CWE-290\` | **Status:** \`CONFIRMED\`
- **Description:** DMARC policy does not reject spoofed emails.
- **Remediation:** Advance DMARC policy to p=quarantine, then p=reject.
`;
