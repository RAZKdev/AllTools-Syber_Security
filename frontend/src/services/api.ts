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

export type EnforcementStatus =
  | 'not_checked'
  | 'checking'
  | 'default_deny_verified'
  | 'probe_allowed'
  | 'unavailable'
  | 'demo';

export interface ScopeGuardProbeResult {
  status: EnforcementStatus;
  isVerified: boolean;
  reason: string;
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
const DEFAULT_TIMEOUT_MS = 8000;

async function fetchWithTimeout(
  input: RequestInfo | URL,
  init: RequestInit = {},
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } finally {
    window.clearTimeout(timeoutId);
  }
}

async function handleResponse<T>(res: Response, endpoint: string): Promise<T> {
  if (!res.ok) {
    let errorDetail = res.statusText || `HTTP ${res.status}`;
    try {
      const errJson = await res.json();
      errorDetail = errJson.detail || errJson.message || JSON.stringify(errJson);
    } catch {
      // Use status text if body is not JSON
    }
    throw new ApiError(errorDetail, res.status, endpoint);
  }
  try {
    return (await res.json()) as T;
  } catch {
    throw new ApiError('Backend returned an invalid JSON response.', res.status, endpoint);
  }
}

export const api = {
  async getHealth(): Promise<HealthResponse> {
    const res = await fetchWithTimeout('/health', {}, 4000);
    const health = await handleResponse<HealthResponse>(res, '/health');
    if (health.status !== 'healthy') {
      throw new ApiError(`Health check returned status '${health.status}'.`, 200, '/health');
    }
    return health;
  },

  async probeScopeGuard(assessmentId: string): Promise<ScopeGuardProbeResult> {
    // The only enforcement claim this UI is allowed to make is based on the
    // backend rejecting a sentinel target that must never be in scope.
    try {
      const negativeRes = await api.evaluateScope(
        assessmentId,
        'scopeguard-probe.invalid',
      );
      if (negativeRes.decision === 'BLOCK') {
        return {
          status: 'default_deny_verified',
          isVerified: true,
          reason:
            'Backend denied the out-of-scope sentinel target. Default-deny verified for this assessment.',
        };
      }
      return {
        status: 'probe_allowed',
        isVerified: false,
        reason:
          'Backend allowed the out-of-scope sentinel target. Enforcement is unverified.',
      };
    } catch (err: any) {
      const detail =
        err?.message || 'Scope Guard probe request failed. Enforcement unavailable.';
      return {
        status: 'unavailable',
        isVerified: false,
        reason: detail,
      };
    }
  },

  async getAssessmentScope(assessmentId: string): Promise<ScopeItem[]> {
    const res = await fetchWithTimeout(`${API_BASE}/assessments/${assessmentId}/scope`);
    return handleResponse<ScopeItem[]>(res, `${API_BASE}/assessments/${assessmentId}/scope`);
  },

  async getRules(): Promise<SecurityRuleMetadata[]> {
    const res = await fetchWithTimeout(`${API_BASE}/executions/rules`);
    return handleResponse<SecurityRuleMetadata[]>(res, `${API_BASE}/executions/rules`);
  },

  async getEngagements(): Promise<Engagement[]> {
    const res = await fetchWithTimeout(`${API_BASE}/engagements`);
    return handleResponse<Engagement[]>(res, `${API_BASE}/engagements`);
  },

  async createEngagement(data: Partial<Engagement>): Promise<Engagement> {
    const res = await fetchWithTimeout(`${API_BASE}/engagements`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return handleResponse<Engagement>(res, `${API_BASE}/engagements`);
  },

  async getAssessments(engagementId?: string): Promise<Assessment[]> {
    const url = engagementId ? `${API_BASE}/assessments?engagementId=${engagementId}` : `${API_BASE}/assessments`;
    const res = await fetchWithTimeout(url);
    return handleResponse<Assessment[]>(res, url);
  },

  async createAssessment(data: Partial<Assessment>): Promise<Assessment> {
    const res = await fetchWithTimeout(`${API_BASE}/assessments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return handleResponse<Assessment>(res, `${API_BASE}/assessments`);
  },

  async getScopeItems(engagementId?: string): Promise<ScopeItem[]> {
    const url = engagementId ? `${API_BASE}/scope/items?engagementId=${engagementId}` : `${API_BASE}/scope/items`;
    const res = await fetchWithTimeout(url);
    return handleResponse<ScopeItem[]>(res, url);
  },

  async createScopeItem(data: Partial<ScopeItem>): Promise<ScopeItem> {
    const res = await fetchWithTimeout(`${API_BASE}/scope/items`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return handleResponse<ScopeItem>(res, `${API_BASE}/scope/items`);
  },

  async evaluateScope(assessmentId: string, target: string): Promise<ScopeEvaluationResult> {
    const res = await fetchWithTimeout(`${API_BASE}/scope/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assessmentId, target }),
    });
    return handleResponse<ScopeEvaluationResult>(res, `${API_BASE}/scope/evaluate`);
  },

  async runPreFlightCheck(assessmentId: string, ruleId: string, target: string): Promise<PreFlightCheckResponse> {
    const res = await fetchWithTimeout(`${API_BASE}/executions/pre-flight`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assessmentId, ruleId, target }),
    });
    return handleResponse<PreFlightCheckResponse>(res, `${API_BASE}/executions/pre-flight`);
  },

  async runCheck(assessmentId: string, ruleId: string, target: string, simulatedData?: any): Promise<RunCheckResponse> {
    const res = await fetchWithTimeout(`${API_BASE}/executions/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assessmentId, ruleId, target, simulatedData }),
    });
    return handleResponse<RunCheckResponse>(res, `${API_BASE}/executions/run`);
  },

  async getExecutions(assessmentId?: string): Promise<CheckExecutionRecord[]> {
    const url = assessmentId ? `${API_BASE}/executions?assessment_id=${assessmentId}` : `${API_BASE}/executions`;
    const res = await fetchWithTimeout(url);
    return handleResponse<CheckExecutionRecord[]>(res, url);
  },

  async getFindings(assessmentId?: string): Promise<Finding[]> {
    const url = assessmentId ? `${API_BASE}/findings?assessmentId=${assessmentId}` : `${API_BASE}/findings`;
    const res = await fetchWithTimeout(url);
    return handleResponse<Finding[]>(res, url);
  },

  async getFinding(findingId: string): Promise<Finding> {
    const url = `${API_BASE}/findings/${findingId}`;
    const res = await fetchWithTimeout(url);
    return handleResponse<Finding>(res, url);
  },

  async getEvidence(assessmentId?: string, findingId?: string): Promise<Evidence[]> {
    const params = new URLSearchParams();
    if (assessmentId) params.append('assessmentId', assessmentId);
    if (findingId) params.append('findingId', findingId);
    const url = `${API_BASE}/evidence?${params.toString()}`;
    const res = await fetchWithTimeout(url);
    return handleResponse<Evidence[]>(res, url);
  },

  async getReportMarkdown(assessmentId: string): Promise<string> {
    const url = `${API_BASE}/reports/${assessmentId}/markdown`;
    const res = await fetchWithTimeout(url);
    if (!res.ok) {
      throw new ApiError(res.statusText, res.status, url);
    }
    return res.text();
  },

  async getReportHtml(assessmentId: string): Promise<string> {
    const url = `${API_BASE}/reports/${assessmentId}/html`;
    const res = await fetchWithTimeout(url);
    if (!res.ok) {
      throw new ApiError(res.statusText, res.status, url);
    }
    return res.text();
  },
};
