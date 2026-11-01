export interface HealthResponse {
  status: string;
  service: string;
  timestamp: string;
  version: string;
}

export interface SecurityRuleMetadata {
  ruleId: string;
  title: string;
  category: string;
  cwe: string;
  description: string;
}

export interface Engagement {
  id: string;
  workspaceId: string;
  name: string;
  description?: string;
  assessor?: string;
  status: string;
  startsAt?: string;
  endsAt?: string;
  rulesOfEngagement?: string;
  createdAt: string;
}

export interface Assessment {
  id: string;
  engagementId: string;
  name: string;
  type?: string;
  status: string;
  startedAt?: string;
  completedAt?: string;
  createdAt: string;
}

export interface ScopeItem {
  id: string;
  engagementId: string;
  type: string;
  value: string;
  environment?: string;
  inScope: boolean;
  notes?: string;
  expiresAt?: string;
}

export interface ScopeEvaluationResult {
  assessmentId: string;
  target: string;
  decision: 'ALLOW' | 'BLOCK';
  reason: string;
  matchedScopeItemId?: string;
  evaluatedAt: string;
}

export interface CheckExecutionRecord {
  id: string;
  assessmentId: string;
  ruleId: string;
  target: string;
  scopeDecision: 'ALLOW' | 'BLOCK';
  status: string;
  ruleVersion?: string;
  durationMs?: number;
  errorCode?: string;
  errorMessage?: string;
  executedAt: string;
}

export interface PreFlightCheckResponse {
  allowed: boolean;
  executionRecord: CheckExecutionRecord;
  message: string;
}

export type ScopeGuardVerificationStatus =
  | 'VERIFIED_ACTIVE'
  | 'NO_ACTIVE_ALLOW_RULE'
  | 'UNVERIFIED'
  | 'CHECKING';

export interface ScopeGuardProbeResult {
  status: ScopeGuardVerificationStatus;
  isVerified: boolean;
  reason: string;
  positiveTarget?: string;
}

export interface Finding {
  id: string;
  assessmentId: string;
  assetId: string;
  ruleId?: string;
  title: string;
  description?: string;
  status: string;
  severity: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'low' | 'medium' | 'high';
  cwe?: string;
  cve?: string;
  cvss?: number;
  impact?: string;
  recommendation?: string;
  createdAt: string;
  updatedAt?: string;
}

export interface Evidence {
  id: string;
  assessmentId: string;
  findingId?: string;
  type: string;
  source?: string;
  artifactPath?: string;
  capturedAt: string;
  sha256: string;
  redacted?: boolean;
  notes?: string;
}

export interface RunCheckResponse {
  allowed: boolean;
  executionRecord: CheckExecutionRecord;
  observation?: {
    id: string;
    summary: string;
    details?: Record<string, any>;
    observedAt: string;
  };
  finding?: Finding;
  evidence?: Evidence;
  message: string;
}

export class ApiError extends Error {
  public status: number;
  public endpoint: string;

  constructor(message: string, status: number, endpoint: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.endpoint = endpoint;
  }
}

const API_BASE = '/api/v1';

async function handleResponse<T>(res: Response, endpoint: string): Promise<T> {
  if (!res.ok) {
    let errorDetail = res.statusText;
    try {
      const errJson = await res.json();
      errorDetail = errJson.detail || errJson.message || JSON.stringify(errJson);
    } catch {
      // Use status text if body not json
    }
    throw new ApiError(errorDetail, res.status, endpoint);
  }
  return res.json();
}

export const api = {
  async getHealth(): Promise<HealthResponse> {
    const res = await fetch('/health');
    return handleResponse<HealthResponse>(res, '/health');
  },

  async probeScopeGuard(assessmentId = 'ASM-001'): Promise<ScopeGuardProbeResult> {
    try {
      // Step 1: Negative Assertion (Sentinel out-of-scope target must evaluate to BLOCK)
      const negativeRes = await api.evaluateScope(assessmentId, 'scopeguard-probe.invalid');
      if (negativeRes.decision !== 'BLOCK') {
        return {
          status: 'UNVERIFIED',
          isVerified: false,
          reason: 'Scope Guard failed negative assertion: Unknown probe target was not BLOCKED.',
        };
      }

      // Step 2: Fetch scope items to locate an active, unexpired, in-scope rule
      const scopeItems = await api.getAssessmentScope(assessmentId).catch(() => []);
      const now = new Date();
      const activeInScopeRule = scopeItems.find((item) => {
        if (!item.inScope) return false;
        if (item.expiresAt && new Date(item.expiresAt) <= now) return false;
        return true;
      });

      if (!activeInScopeRule) {
        return {
          status: 'NO_ACTIVE_ALLOW_RULE',
          isVerified: false,
          reason: 'Default-deny boundary verified, but no active in-scope rules exist to verify positive ALLOW path.',
        };
      }

      // Extract positive test target based on active rule
      let positiveTarget = activeInScopeRule.value.trim();
      if (activeInScopeRule.type === 'cidr') {
        const ipPart = positiveTarget.split('/')[0];
        const segments = ipPart.split('.');
        if (segments.length === 4) {
          segments[3] = '1';
          positiveTarget = segments.join('.');
        }
      } else if (activeInScopeRule.type === 'subdomain' && positiveTarget.startsWith('*.')) {
        positiveTarget = 'test.' + positiveTarget.slice(2);
      }

      // Step 3: Positive Assertion (Authorized target must evaluate to ALLOW)
      const positiveRes = await api.evaluateScope(assessmentId, positiveTarget);
      if (positiveRes.decision === 'ALLOW') {
        return {
          status: 'VERIFIED_ACTIVE',
          isVerified: true,
          reason: `Dual verification passed: '${positiveTarget}' allowed under rule '${activeInScopeRule.id}', sentinel probe blocked.`,
          positiveTarget,
        };
      }

      return {
        status: 'UNVERIFIED',
        isVerified: false,
        reason: `Scope Guard failed positive assertion: In-scope target '${positiveTarget}' was rejected (${positiveRes.reason}).`,
        positiveTarget,
      };
    } catch (err: any) {
      return {
        status: 'UNVERIFIED',
        isVerified: false,
        reason: `Scope Guard probe evaluation failed: ${err.message || String(err)}`,
      };
    }
  },

  async getAssessmentScope(assessmentId: string): Promise<ScopeItem[]> {
    const res = await fetch(`${API_BASE}/assessments/${assessmentId}/scope`);
    return handleResponse<ScopeItem[]>(res, `${API_BASE}/assessments/${assessmentId}/scope`);
  },

  async getRules(): Promise<SecurityRuleMetadata[]> {
    const res = await fetch(`${API_BASE}/executions/rules`);
    return handleResponse<SecurityRuleMetadata[]>(res, `${API_BASE}/executions/rules`);
  },

  async getEngagements(): Promise<Engagement[]> {
    const res = await fetch(`${API_BASE}/engagements`);
    return handleResponse<Engagement[]>(res, `${API_BASE}/engagements`);
  },

  async createEngagement(data: Partial<Engagement>): Promise<Engagement> {
    const res = await fetch(`${API_BASE}/engagements`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return handleResponse<Engagement>(res, `${API_BASE}/engagements`);
  },

  async getAssessments(engagementId?: string): Promise<Assessment[]> {
    const url = engagementId ? `${API_BASE}/assessments?engagementId=${engagementId}` : `${API_BASE}/assessments`;
    const res = await fetch(url);
    return handleResponse<Assessment[]>(res, url);
  },

  async createAssessment(data: Partial<Assessment>): Promise<Assessment> {
    const res = await fetch(`${API_BASE}/assessments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return handleResponse<Assessment>(res, `${API_BASE}/assessments`);
  },

  async getScopeItems(engagementId?: string): Promise<ScopeItem[]> {
    const url = engagementId ? `${API_BASE}/scope/items?engagementId=${engagementId}` : `${API_BASE}/scope/items`;
    const res = await fetch(url);
    return handleResponse<ScopeItem[]>(res, url);
  },

  async createScopeItem(data: Partial<ScopeItem>): Promise<ScopeItem> {
    const res = await fetch(`${API_BASE}/scope/items`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return handleResponse<ScopeItem>(res, `${API_BASE}/scope/items`);
  },

  async evaluateScope(assessmentId: string, target: string): Promise<ScopeEvaluationResult> {
    const res = await fetch(`${API_BASE}/scope/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assessmentId, target }),
    });
    return handleResponse<ScopeEvaluationResult>(res, `${API_BASE}/scope/evaluate`);
  },

  async runPreFlightCheck(assessmentId: string, ruleId: string, target: string): Promise<PreFlightCheckResponse> {
    const res = await fetch(`${API_BASE}/executions/pre-flight`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assessmentId, ruleId, target }),
    });
    return handleResponse<PreFlightCheckResponse>(res, `${API_BASE}/executions/pre-flight`);
  },

  async runCheck(assessmentId: string, ruleId: string, target: string, simulatedData?: any): Promise<RunCheckResponse> {
    const res = await fetch(`${API_BASE}/executions/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assessmentId, ruleId, target, simulatedData }),
    });
    return handleResponse<RunCheckResponse>(res, `${API_BASE}/executions/run`);
  },

  async getExecutions(assessmentId?: string): Promise<CheckExecutionRecord[]> {
    const url = assessmentId ? `${API_BASE}/executions?assessment_id=${assessmentId}` : `${API_BASE}/executions`;
    const res = await fetch(url);
    return handleResponse<CheckExecutionRecord[]>(res, url);
  },

  async getFindings(assessmentId?: string): Promise<Finding[]> {
    const url = assessmentId ? `${API_BASE}/findings?assessmentId=${assessmentId}` : `${API_BASE}/findings`;
    const res = await fetch(url);
    return handleResponse<Finding[]>(res, url);
  },

  async getFinding(findingId: string): Promise<Finding> {
    const url = `${API_BASE}/findings/${findingId}`;
    const res = await fetch(url);
    return handleResponse<Finding>(res, url);
  },

  async getEvidence(assessmentId?: string, findingId?: string): Promise<Evidence[]> {
    const params = new URLSearchParams();
    if (assessmentId) params.append('assessmentId', assessmentId);
    if (findingId) params.append('findingId', findingId);
    const url = `${API_BASE}/evidence?${params.toString()}`;
    const res = await fetch(url);
    return handleResponse<Evidence[]>(res, url);
  },

  async getReportMarkdown(assessmentId: string): Promise<string> {
    const url = `${API_BASE}/reports/${assessmentId}/markdown`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new ApiError(res.statusText, res.status, url);
    }
    return res.text();
  },

  async getReportHtml(assessmentId: string): Promise<string> {
    const url = `${API_BASE}/reports/${assessmentId}/html`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new ApiError(res.statusText, res.status, url);
    }
    return res.text();
  },
};
