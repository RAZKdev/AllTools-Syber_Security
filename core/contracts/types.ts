/**
 * Human-readable TypeScript contract index.
 *
 * Canonical serialized shapes live in core/contracts/schemas/*.schema.json.
 * This file intentionally contains only stable aliases used by the frontend
 * while generated/runtime validation remains based on JSON Schema.
 */

export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export type Confidence = 'low' | 'medium' | 'high';
export type ExecutionStatus =
  | 'PASS'
  | 'FAIL'
  | 'WARN'
  | 'NOT_TESTED'
  | 'ERROR'
  | 'BLOCKED_OUT_OF_SCOPE'
  | 'INSUFFICIENT_DATA';

export type FindingStatus =
  | 'DETECTED'
  | 'NEEDS_REVIEW'
  | 'CONFIRMED'
  | 'FALSE_POSITIVE'
  | 'ACCEPTED_RISK'
  | 'MITIGATED'
  | 'REMEDIATION'
  | 'RETEST_REQUIRED'
  | 'RESOLVED'
  | 'REGRESSION';

export interface AssetRef {
  id: string;
  name: string;
}

export interface FindingSummary {
  id: string;
  assetId: string;
  title: string;
  status: FindingStatus;
  severity: Severity;
  confidence: Confidence;
  priority?: Severity;
}

export interface CheckResultSummary {
  id: string;
  ruleId: string;
  target: string;
  scopeDecision: 'ALLOW' | 'BLOCK';
  status: ExecutionStatus;
  executedAt: string;
}
