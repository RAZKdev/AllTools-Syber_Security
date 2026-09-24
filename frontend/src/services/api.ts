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

const API_BASE = '/api/v1';

export const api = {
  async getEngagements(): Promise<Engagement[]> {
    const res = await fetch(`${API_BASE}/engagements`);
    if (!res.ok) throw new Error('Failed to fetch engagements');
    return res.json();
  },

  async createEngagement(data: Partial<Engagement>): Promise<Engagement> {
    const res = await fetch(`${API_BASE}/engagements`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error('Failed to create engagement');
    return res.json();
  },

  async getAssessments(engagementId?: string): Promise<Assessment[]> {
    const url = engagementId ? `${API_BASE}/assessments?engagementId=${engagementId}` : `${API_BASE}/assessments`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch assessments');
    return res.json();
  },

  async createAssessment(data: Partial<Assessment>): Promise<Assessment> {
    const res = await fetch(`${API_BASE}/assessments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error('Failed to create assessment');
    return res.json();
  },

  async getScopeItems(engagementId?: string): Promise<ScopeItem[]> {
    const url = engagementId ? `${API_BASE}/scope/items?engagementId=${engagementId}` : `${API_BASE}/scope/items`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch scope items');
    return res.json();
  },

  async createScopeItem(data: Partial<ScopeItem>): Promise<ScopeItem> {
    const res = await fetch(`${API_BASE}/scope/items`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error('Failed to create scope item');
    return res.json();
  },

  async evaluateScope(assessmentId: string, target: string): Promise<ScopeEvaluationResult> {
    const res = await fetch(`${API_BASE}/scope/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assessmentId, target }),
    });
    if (!res.ok) throw new Error('Failed to evaluate scope');
    return res.json();
  },

  async runPreFlightCheck(assessmentId: string, ruleId: string, target: string): Promise<PreFlightCheckResponse> {
    const res = await fetch(`${API_BASE}/executions/pre-flight`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assessmentId, ruleId, target }),
    });
    if (!res.ok) throw new Error('Failed to run pre-flight check');
    return res.json();
  },

  async runCheck(assessmentId: string, ruleId: string, target: string, simulatedData?: any): Promise<RunCheckResponse> {
    const res = await fetch(`${API_BASE}/executions/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assessmentId, ruleId, target, simulatedData }),
    });
    if (!res.ok) throw new Error('Failed to run check');
    return res.json();
  },

  async getExecutions(assessmentId?: string): Promise<CheckExecutionRecord[]> {
    const url = assessmentId ? `${API_BASE}/executions?assessment_id=${assessmentId}` : `${API_BASE}/executions`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch executions');
    return res.json();
  },

  async getFindings(assessmentId?: string): Promise<Finding[]> {
    const url = assessmentId ? `${API_BASE}/findings?assessmentId=${assessmentId}` : `${API_BASE}/findings`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch findings');
    return res.json();
  },

  async getFinding(findingId: string): Promise<Finding> {
    const res = await fetch(`${API_BASE}/findings/${findingId}`);
    if (!res.ok) throw new Error('Failed to fetch finding');
    return res.json();
  },

  async getEvidence(assessmentId?: string, findingId?: string): Promise<Evidence[]> {
    const params = new URLSearchParams();
    if (assessmentId) params.append('assessmentId', assessmentId);
    if (findingId) params.append('findingId', findingId);
    const res = await fetch(`${API_BASE}/evidence?${params.toString()}`);
    if (!res.ok) throw new Error('Failed to fetch evidence');
    return res.json();
  },

  async getReportMarkdown(assessmentId: string): Promise<string> {
    const res = await fetch(`${API_BASE}/reports/${assessmentId}/markdown`);
    if (!res.ok) throw new Error('Failed to fetch Markdown report');
    return res.text();
  },

  async getReportHtml(assessmentId: string): Promise<string> {
    const res = await fetch(`${API_BASE}/reports/${assessmentId}/html`);
    if (!res.ok) throw new Error('Failed to fetch HTML report');
    return res.text();
  },
};
