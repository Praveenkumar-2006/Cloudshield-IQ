/**
 * CloudShield IQ — Centralized API Client
 * ========================================
 * Type-safe API communication layer connecting the tactical React dashboard
 * to the FastAPI backend services.
 */

import { API_BASE, DEFAULT_TIMEOUT_MS, UPLOAD_TIMEOUT_MS } from './config';

export interface HealthData {
  status: 'ok' | 'degraded' | 'offline' | 'checking';
  service: string;
  version: string;
  latency?: number;
  timestamp?: string;
  error?: string;
}

export interface IngestionResult {
  filename: string;
  status: string;
  total_parsed: number;
  successful_events: number;
  failed_events: number;
  duration_ms: number;
  risk_summary: {
    average_risk_score: number;
    anomalies_detected: number;
    findings_count: number;
    high_critical_count: number;
  };
  findings_generated: Array<{
    finding_id: string;
    title: string;
    cloud: 'AWS' | 'Azure' | 'GCP' | string;
    resourceId: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    category: string;
    riskScore: number;
    complianceViolation: string[];
    remediation: string;
    cliCommand?: string;
    terraform?: string;
  }>;
  sample_events: Array<{
    event_id: string;
    timestamp: string;
    cloud_provider: string;
    action: string;
    canonical_action: string;
    actor_name: string;
    resource_id: string;
  }>;
}

export interface IngestionStats {
  total_events_ingested: number;
  valid_events_count: number;
  invalid_records_count: number;
  anomalies_detected: number;
  critical_findings_count: number;
  high_findings_count: number;
  medium_findings_count: number;
  low_findings_count: number;
  average_risk_score: number;
  provider_distribution: Record<string, number>;
  last_ingestion_time?: string;
}

export interface TelemetryEvent {
  event_id: string;
  timestamp: string;
  cloud_provider: string;
  resource_type: string;
  resource_id: string;
  raw_action: string;
  canonical_action: string;
  actor_type: string;
  actor_name: string;
  outcome: string;
  mfa_used?: boolean;
  source_ip?: string;
}

export interface Finding {
  id: string;
  title: string;
  cloud: 'AWS' | 'Azure' | 'GCP';
  resourceId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  riskScore: number;
  shapTopFeature: string;
  shapImpact: number;
  complianceViolation: string[];
  remediation: string;
  cliCommand: string;
  terraform: string;
  pythonSnippet?: string;
  attackVector?: string;
  status?: string;
  detected_at?: string;
  resolved_at?: string;
}

export interface SecurityExplanation {
  finding_id: string;
  risk: string;
  what_happened: string;
  why_it_matters: string;
  evidence: string[];
  compliance_impact: string;
  recommended_action: string;
  grounding_score: number;
  is_llm_generated: boolean;
  generated_at: string;
  model_used?: string;
}

export interface ComplianceSummary {
  overall_pass_rate: number;
  total_controls: number;
  passed_controls: number;
  failed_controls: number;
  partial_controls: number;
  framework_scores: Record<string, number>;
  evaluated_at: string;
}

export interface ComplianceControlItem {
  id: string;
  name: string;
  framework: string;
  cloud_provider?: string;
  status: 'PASS' | 'FAIL' | 'PARTIAL';
  evaluatedResources: number;
  failedCount: number;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  remediation?: string;
  cliCommand?: string;
  terraform?: string;
}

export interface ComplianceReport {
  report_title: string;
  version: string;
  generated_at: string;
  summary: {
    overall_pass_rate_percent: number;
    total_controls_evaluated: number;
    passed_controls: number;
    failed_controls: number;
    partial_controls: number;
    framework_scores: Record<string, number>;
  };
  control_evaluations: Array<{
    control_id: string;
    control_name: string;
    framework: string;
    cloud_provider: string;
    status: string;
    severity: string;
    evaluated_resources_count?: number;
    failed_resources?: string[];
    remediation_guidance: string;
    cli_command?: string;
    terraform_snippet?: string;
  }>;
}

export interface GlobalShapAttributions {
  model_version: string;
  base_value: number;
  sample_count_analyzed: number;
  top_global_features: Array<{
    feature_name: string;
    display_name: string;
    domain: string;
    mean_abs_shap: number;
    relative_percentage: number;
    description: string;
  }>;
  domain_distribution: Record<string, number>;
}

// ----------------------------------------------------------------------------
// Health Check
// ----------------------------------------------------------------------------
export async function checkBackendHealth(): Promise<HealthData> {
  const start = performance.now();
  try {
    const res = await fetch(`${API_BASE}/health`, {
      method: 'GET',
      signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
    });
    const latency = Math.round(performance.now() - start);
    if (res.ok) {
      const data = await res.json();
      return {
        status: data.status === 'ok' ? 'ok' : 'degraded',
        service: data.service || 'cloudshield-iq-api',
        version: data.version || '0.1.0',
        latency,
        timestamp: new Date().toLocaleTimeString(),
      };
    }
    return {
      status: 'degraded',
      service: 'cloudshield-iq-api',
      version: '0.1.0',
      latency,
      timestamp: new Date().toLocaleTimeString(),
      error: `HTTP ${res.status}`,
    };
  } catch (err: any) {
    return {
      status: 'offline',
      service: 'cloudshield-iq-api',
      version: '0.1.0',
      timestamp: new Date().toLocaleTimeString(),
      error: err.name === 'TimeoutError' ? 'Connection timed out' : 'API unreachable',
    };
  }
}

// ----------------------------------------------------------------------------
// Ingestion API
// ----------------------------------------------------------------------------
export async function uploadTelemetryFile(file: File): Promise<IngestionResult> {
  const formData = new FormData();
  formData.append('file', file);

  // IMPORTANT: Do NOT set Content-Type header so the browser includes boundary
  const res = await fetch(`${API_BASE}/ingestion/upload`, {
    method: 'POST',
    body: formData,
    signal: AbortSignal.timeout(UPLOAD_TIMEOUT_MS),
  });

  if (!res.ok) {
    let errorDetail = `Upload failed with status HTTP ${res.status}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) {
        errorDetail = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {
      // fallback
    }
    throw new Error(errorDetail);
  }

  return res.json();
}

export async function loadSampleBenchmark(sampleType: string): Promise<IngestionResult> {
  const res = await fetch(`${API_BASE}/ingestion/sample/${encodeURIComponent(sampleType)}`, {
    method: 'POST',
    signal: AbortSignal.timeout(UPLOAD_TIMEOUT_MS),
  });

  if (!res.ok) {
    let detail = `Failed to load sample ${sampleType}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) detail = errJson.detail;
    } catch {
      // ignore
    }
    throw new Error(detail);
  }

  return res.json();
}

export async function fetchIngestionStats(): Promise<IngestionStats> {
  const res = await fetch(`${API_BASE}/ingestion/stats`, {
    method: 'GET',
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function fetchIngestedEvents(
  limit: number = 50,
  offset: number = 0,
  provider?: string
): Promise<{ total: number; events: TelemetryEvent[] }> {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (provider && provider.toUpperCase() !== 'ALL') {
    params.set('provider', provider.toLowerCase());
  }

  const res = await fetch(`${API_BASE}/ingestion/events?${params.toString()}`, {
    method: 'GET',
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ----------------------------------------------------------------------------
// Findings API
// ----------------------------------------------------------------------------
export async function fetchFindings(params?: {
  cloud?: string;
  severity?: string;
  category?: string;
  status?: string;
  search?: string;
  limit?: number;
  includeFallback?: boolean;
}): Promise<{ total: number; findings: Finding[]; data_source?: string }> {
  const query = new URLSearchParams();
  if (params?.cloud && params.cloud !== 'ALL') query.set('cloud', params.cloud);
  if (params?.severity && params.severity !== 'ALL') query.set('severity', params.severity);
  if (params?.category && params.category !== 'ALL') query.set('category', params.category);
  if (params?.status && params.status !== 'ALL') query.set('status', params.status);
  if (params?.search) query.set('search', params.search);
  if (params?.limit) query.set('limit', String(params.limit));
  if (params?.includeFallback) query.set('include_fallback', 'true');

  const url = `${API_BASE}/findings${query.toString() ? `?${query.toString()}` : ''}`;
  const res = await fetch(url, {
    method: 'GET',
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });

  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();

  // Normalize raw backend finding models into typed frontend Finding interface
  const mappedFindings: Finding[] = (data.findings || []).map((f: any) => ({
    id: f.finding_id || f.id,
    title: f.title,
    cloud: (f.cloud_provider || f.cloud || 'AWS').toUpperCase() as 'AWS' | 'Azure' | 'GCP',
    resourceId: f.resource_id || f.resourceId || '',
    severity: (f.severity || 'MEDIUM').toUpperCase() as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
    category: f.category || 'General',
    riskScore: typeof f.risk_score === 'number' ? f.risk_score : (f.riskScore || 50),
    shapTopFeature: f.shap_top_feature || f.shapTopFeature || 'baseline_activity',
    shapImpact: typeof f.shap_impact === 'number' ? f.shap_impact : (f.shapImpact || 0.1),
    complianceViolation: Array.isArray(f.compliance_violations) ? f.compliance_violations : [],
    remediation: f.remediation_guidance || f.remediation || '',
    cliCommand: f.cli_remediation_command || f.cliCommand || '',
    terraform: f.terraform_remediation_snippet || f.terraform || '',
    status: f.status || 'OPEN',
  }));

  return {
    total: typeof data.total === 'number' ? data.total : mappedFindings.length,
    findings: mappedFindings,
    data_source: data.data_source || 'database',
  };
}

export async function fetchFindingById(findingId: string): Promise<Finding> {
  const res = await fetch(`${API_BASE}/findings/${encodeURIComponent(findingId)}`, {
    method: 'GET',
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const f = await res.json();
  return {
    id: f.finding_id || f.id,
    title: f.title,
    cloud: (f.cloud_provider || f.cloud || 'AWS').toUpperCase() as 'AWS' | 'Azure' | 'GCP',
    resourceId: f.resource_id || f.resourceId || '',
    severity: (f.severity || 'MEDIUM').toUpperCase() as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
    category: f.category || 'General',
    riskScore: typeof f.risk_score === 'number' ? f.risk_score : (f.riskScore || 50),
    shapTopFeature: f.shap_top_feature || f.shapTopFeature || 'baseline_activity',
    shapImpact: typeof f.shap_impact === 'number' ? f.shap_impact : (f.shapImpact || 0.1),
    complianceViolation: Array.isArray(f.compliance_violations) ? f.compliance_violations : [],
    remediation: f.remediation_guidance || f.remediation || '',
    cliCommand: f.cli_remediation_command || f.cliCommand || '',
    terraform: f.terraform_remediation_snippet || f.terraform || '',
    status: f.status || 'OPEN',
  };
}

export async function explainFinding(findingId: string): Promise<SecurityExplanation> {
  const res = await fetch(`${API_BASE}/findings/${encodeURIComponent(findingId)}/explain`, {
    method: 'POST',
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function updateFindingStatus(
  findingId: string,
  newStatus: string
): Promise<{ finding_id: string; status: string; resolved_at?: string; message: string }> {
  const res = await fetch(`${API_BASE}/findings/${encodeURIComponent(findingId)}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: newStatus }),
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ----------------------------------------------------------------------------
// Recommendations API
// ----------------------------------------------------------------------------
export async function fetchPlaybooks(cloud?: string): Promise<any[]> {
  const query = cloud && cloud !== 'ALL' ? `?cloud=${encodeURIComponent(cloud)}` : '';
  const res = await fetch(`${API_BASE}/recommendations/playbooks${query}`, {
    method: 'GET',
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function fetchPlaybookById(playbookId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/recommendations/playbooks/${encodeURIComponent(playbookId)}`, {
    method: 'GET',
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ----------------------------------------------------------------------------
// Compliance API
// ----------------------------------------------------------------------------
export interface ComplianceEvaluationResponse {
  total_controls: number;
  results: ComplianceControlItem[];
  summary: ComplianceSummary;
}

export async function fetchComplianceEvaluations(
  framework?: string,
  cloudProvider?: string
): Promise<ComplianceEvaluationResponse> {
  const query = new URLSearchParams();
  if (framework && framework !== 'ALL') query.set('framework', framework);
  if (cloudProvider && cloudProvider !== 'ALL') query.set('cloud_provider', cloudProvider);

  const url = `${API_BASE}/compliance/evaluations${query.toString() ? `?${query.toString()}` : ''}`;
  const res = await fetch(url, {
    method: 'GET',
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();

  const mappedResults: ComplianceControlItem[] = (data.results || []).map((c: any) => ({
    id: c.control_id,
    name: c.control_name,
    framework: c.framework,
    cloud_provider: c.cloud_provider,
    status: c.status || 'PASS',
    evaluatedResources: typeof c.evaluated_resources === 'number' ? c.evaluated_resources : 0,
    failedCount: typeof c.failed_resources === 'number' ? c.failed_resources : (c.failed_resource_ids?.length || 0),
    severity: (c.severity || 'HIGH').toUpperCase() as 'HIGH' | 'MEDIUM' | 'LOW',
    remediation: c.remediation_guidance || '',
    cliCommand: c.cli_command,
    terraform: c.terraform_snippet,
  }));

  return {
    total_controls: data.total_controls || mappedResults.length,
    results: mappedResults,
    summary: data.summary,
  };
}

export async function fetchComplianceSummary(framework?: string): Promise<ComplianceSummary> {
  const url = framework
    ? `${API_BASE}/compliance/summary?framework=${encodeURIComponent(framework)}`
    : `${API_BASE}/compliance/summary`;
  const res = await fetch(url, {
    method: 'GET',
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function fetchComplianceReport(framework?: string): Promise<ComplianceReport> {
  const url = framework
    ? `${API_BASE}/compliance/report?framework=${encodeURIComponent(framework)}`
    : `${API_BASE}/compliance/report`;
  const res = await fetch(url, {
    method: 'GET',
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function fetchComplianceControls(): Promise<ComplianceControlItem[]> {
  const res = await fetch(`${API_BASE}/compliance/controls`, {
    method: 'GET',
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const raw = await res.json();
  return raw.map((c: any) => ({
    id: c.control_id,
    name: c.control_name,
    framework: c.framework,
    cloud_provider: c.cloud_provider,
    status: 'PASS', // Default catalog status until evaluated
    evaluatedResources: 0,
    failedCount: 0,
    severity: (c.severity || 'HIGH').toUpperCase() as 'HIGH' | 'MEDIUM' | 'LOW',
    remediation: c.remediation_guidance,
    cliCommand: c.cli_command,
    terraform: c.terraform_snippet,
  }));
}

// ----------------------------------------------------------------------------
// Machine Learning & TreeSHAP API
// ----------------------------------------------------------------------------
export async function fetchGlobalShapAttributions(topK: number = 6): Promise<GlobalShapAttributions> {
  const res = await fetch(`${API_BASE}/ml/explain/global?top_k=${topK}`, {
    method: 'GET',
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function explainEventWithShap(eventPayload: any, topK: number = 4): Promise<any> {
  const res = await fetch(`${API_BASE}/ml/explain/event?top_k=${topK}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(eventPayload),
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function fetchModelInfo(): Promise<any> {
  const res = await fetch(`${API_BASE}/ml/model-info`, {
    method: 'GET',
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function fetchRiskModelInfo(): Promise<any> {
  const res = await fetch(`${API_BASE}/ml/risk-model-info`, {
    method: 'GET',
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function triggerLiveRiskScan(payload: any): Promise<any> {
  const res = await fetch(`${API_BASE}/ml/classify-risk`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function triggerAnomalyDetection(events: any[]): Promise<any> {
  const res = await fetch(`${API_BASE}/ml/detect`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(events),
    signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}
