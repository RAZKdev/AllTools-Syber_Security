# DESIGN.md — AllTools-CyberSec Product & UI/UX Design System

## 1. Product Identity

**Name:** AllTools-CyberSec

**Positioning:** Practical Defensive Security Workbench

The product should feel like a serious security operations and assessment workspace, not a hacker-themed toy.

## 2. Design Principles

### 2.1 Evidence First

The interface should prioritize what was observed and how it was verified.

Prefer:

`Evidence → Interpretation → Risk → Action`

over:

`Big Score → Color → Guess`

### 2.2 Clarity Over Drama

Avoid excessive neon, glowing hacker motifs, skulls, Matrix rain, fake terminal decoration, and alarm-heavy styling.

Security products can feel technical without feeling theatrical.

### 2.3 State Must Be Explicit

Always visually distinguish:

- PASS
- FAIL
- WARN
- NOT TESTED
- ERROR
- BLOCKED_OUT_OF_SCOPE
- INSUFFICIENT_DATA

Never communicate a failed execution as a security failure.

### 2.4 Severity Is Not Priority

Severity, confidence, asset criticality, exposure, and remediation status should appear as separate fields.

Do not combine them into one ambiguous badge.

### 2.5 Progressive Disclosure

The primary view should be understandable quickly.

Detailed evidence, raw responses, hashes, logs, references, and technical metadata should be available without overwhelming the main workflow.

## 3. Visual Direction

### Overall Character

- dark-first professional interface
- restrained contrast
- technical and precise
- premium but utilitarian
- dense where necessary
- generous spacing around critical actions

### Avoid

- gratuitous gradients
- excessive glassmorphism
- excessive rounded cards
- giant hero sections
- noisy animations
- fake cyber aesthetics

## 4. Information Architecture

```text
Dashboard
├── Workspaces
├── Engagements
│   ├── Scope
│   ├── Assets
│   ├── Assessments
│   └── Timeline
├── Findings
├── Evidence
├── Remediation
├── Retests
├── Baselines
├── Incidents
├── Playbooks
├── Reports
├── Rules
└── Settings
```

## 5. Dashboard Design

Dashboard should answer:

1. What assessments are active?
2. What assets are in scope?
3. What findings need attention?
4. What changed since the baseline?
5. What remediation/retest work is pending?
6. Did any execution fail or get blocked?

Recommended sections:

```text
Active Assessments
Asset Coverage
Findings by Severity
Finding Status
Remediation Queue
Baseline Changes
Recent Activity
Execution Errors / Scope Blocks
```

Avoid making a single "Security Score" the hero metric.

## 6. Assessment UX

Primary workflow:

```text
Create Engagement
↓
Define Scope
↓
Register Assets
↓
Create Assessment
↓
Select Checks
↓
Review Scope
↓
Run
↓
Review Observations
↓
Validate Findings
↓
Assess Risk
↓
Remediate
↓
Retest
↓
Report
```

Each stage should show current status and allow navigation back without losing state.

## 7. Scope Guard UX

Scope is a first-class security control.

When a target is blocked, show:

```text
BLOCKED — OUT OF SCOPE

Target:
...

Reason:
Target does not match the active assessment scope.
```

Do not hide the reason behind a generic error message.

## 8. Finding Detail UX

Every finding detail page should prioritize:

```text
Title
Status
Severity
Confidence
Priority
Asset
Description
Evidence
Impact
Recommendation
References
Remediation
Retest History
Timeline
```

## 9. Evidence UX

Evidence should be traceable.

Display:

- evidence ID
- source/target
- capture time
- collector/check
- related finding
- artifact type
- integrity/hash state

Sensitive content should be redacted by default when appropriate.

## 10. Tables

Security workflows often require tables.

Prioritize:

- scan/check status
- filterability
- sortability
- readable timestamps
- stable IDs
- clear severity/status columns

Avoid overly wide tables that hide important columns on small screens.

## 11. Severity Semantics

Suggested visual semantics:

```text
Critical → strongest visual emphasis
High     → strong emphasis
Medium   → moderate emphasis
Low      → subtle emphasis
Info     → neutral emphasis
```

Do not rely on color alone. Always pair color with labels/icons/text.

## 12. Status Semantics

Use consistent visual language:

```text
PASS
FAIL
WARN
NOT TESTED
ERROR
BLOCKED
INSUFFICIENT DATA
```

The same state must look and behave consistently throughout the application.

## 13. Interaction Rules

Destructive or high-impact actions require confirmation.

Examples:

- deleting an assessment
- deleting evidence
- deleting a finding
- changing scope
- running a target-based action

Prefer archive/status transitions over destructive deletion when history matters.

## 14. Accessibility

Minimum goals:

- keyboard-accessible controls
- visible focus state
- semantic HTML
- readable contrast
- labels for form fields
- non-color-only state communication
- accessible tables
- accessible dialogs

## 15. Responsive Design

The desktop interface is primary because security assessment screens are information-dense, but all core workflows should remain usable on smaller screens.

On smaller screens:

- stack metadata
- convert dense tables to cards or horizontal scrolling
- keep scope/status/findings visible
- do not hide critical security state

## 16. Empty States

Empty states should explain what happens next.

Bad:

`No data.`

Good:

`No assessments yet. Create an engagement and define its authorized scope first.`

## 17. Error States

An error must explain:

- what failed
- whether the target was contacted
- whether scope blocked execution
- whether the result is incomplete
- what action can be taken next

## 18. Data Visualization

Use charts only when they clarify:

- trend over time
- findings distribution
- remediation progress
- baseline changes
- assessment coverage

Do not use charts as decoration.

## 19. Report Design

Reports should be printable and readable without the interactive application.

Recommended structure:

```text
Cover / Metadata
Executive Summary
Scope
Methodology
Asset Summary
Findings
Evidence
Risk Context
Recommendations
Remediation Status
Retest Results
Appendix / References
```

## 20. Design Token Direction

Use semantic tokens rather than hardcoding colors throughout components.

Suggested categories:

```text
background
surface
surface-elevated
border
text-primary
text-secondary
accent
severity-critical
severity-high
severity-medium
severity-low
status-pass
status-warning
status-error
status-blocked
focus
```

Exact color values may be decided during UI implementation, but semantics should remain stable.

## 21. Component Architecture

Prefer reusable components:

```text
StatusBadge
SeverityBadge
ConfidenceBadge
ScopeIndicator
EvidenceCard
FindingTable
FindingDetail
AssessmentTimeline
RiskBreakdown
AssetTable
CheckResult
ConfirmationDialog
FilterBar
EmptyState
ErrorState
```

## 22. UX Quality Gate

Before shipping a frontend change, verify:

- no misleading security status
- no hidden scope decision
- no secret leakage
- no broken loading/error/empty states
- no unnecessary visual complexity
- mobile usability remains acceptable
- keyboard interaction works for critical controls
