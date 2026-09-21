import { useState, useEffect, useMemo, useRef } from 'react';
import {
  AlertTriangle,
  RefreshCw,
  UploadCloud,
  Terminal,
  Activity,
  Copy,
  Check,
  X,
  Send,
  Menu,
  CheckCircle2,
  Download,
  Play,
  Pause,
  Search,
  Shield,
  ShieldAlert,
  Server,
  Layers,
  Sliders,
  Sparkles,
  FolderUp
} from 'lucide-react';
import {
  checkBackendHealth as apiCheckBackendHealth,
  uploadTelemetryFile as apiUploadTelemetryFile,
  loadSampleBenchmark as apiLoadSampleBenchmark,
  fetchIngestionStats as apiFetchIngestionStats,
  fetchIngestedEvents as apiFetchIngestedEvents,
  fetchFindings as apiFetchFindings,
  explainFinding as apiExplainFinding,
  updateFindingStatus as apiUpdateFindingStatus,
  fetchComplianceReport as apiFetchComplianceReport,
  fetchComplianceEvaluations as apiFetchComplianceEvaluations,
  fetchGlobalShapAttributions as apiFetchGlobalShapAttributions,
  explainEventWithShap as apiExplainEventWithShap,
  fetchModelInfo as apiFetchModelInfo,
  fetchRiskModelInfo as apiFetchRiskModelInfo,
  triggerLiveRiskScan as apiTriggerLiveRiskScan,
  triggerAnomalyDetection as apiTriggerAnomalyDetection,
} from './api/client';
import type {
  IngestionResult,
  IngestionStats,
  TelemetryEvent,
  Finding,
} from './api/client';

interface SecurityExplanation {
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

interface HealthData {
  status: 'ok' | 'degraded' | 'offline' | 'checking';
  service: string;
  version: string;
  latency?: number;
  timestamp?: string;
  error?: string;
}

interface ComplianceControl {
  id: string;
  name: string;
  framework: string;
  status: 'PASS' | 'FAIL' | 'PARTIAL';
  evaluatedResources: number;
  failedCount: number;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  remediation?: string;
  cliCommand?: string;
  terraform?: string;
  evidence?: string[];
}

interface SecOpsMessage {
  id: string;
  sender: 'operator' | 'system';
  text: string;
  code?: string;
  codeLang?: string;
  timestamp: string;
}

export function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'compliance' | 'ml-engine' | 'ingestion' | 'architecture'>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [findingsSource, setFindingsSource] = useState<'database' | 'ingested_memory' | 'offline_fallback' | 'empty'>('empty');
  const [isLoadingFindings, setIsLoadingFindings] = useState(false);
  const [selectedCloudFilter, setSelectedCloudFilter] = useState<'ALL' | 'AWS' | 'Azure' | 'GCP'>('ALL');
  const [selectedSeverityFilter, setSelectedSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Tactical Operations HUD & Stream states
  const [utcTime, setUtcTime] = useState(new Date().toUTCString().replace('GMT', 'UTC'));
  const [isLiveStreamActive, setIsLiveStreamActive] = useState(true);
  const [telemetryFilter, setTelemetryFilter] = useState<'ALL' | 'AWS' | 'AZURE' | 'GCP' | 'CRIT'>('ALL');

  // Tactical Toast Notifications
  const [toasts, setToasts] = useState<Array<{ id: string; message: string; type?: 'info' | 'success' | 'warn' }>>([]);
  const toastSeqRef = useRef(0);
  const showToast = (message: string, type: 'info' | 'success' | 'warn' = 'info') => {
    toastSeqRef.current += 1;
    const id = `${Date.now()}-${toastSeqRef.current}`;
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 3500);
  };

  // Command Palette state (Ctrl+K)
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);
  const [paletteQuery, setPaletteQuery] = useState('');

  // Finding Remediation & Lifecycle Triage states
  const [selectedCategoryFilter, setSelectedCategoryFilter] = useState<string>('ALL');
  const [findingStatuses, setFindingStatuses] = useState<Record<string, 'OPEN' | 'IN_PROGRESS' | 'RESOLVED'>>({});

  // Compliance States
  const [complianceStatusFilter, setComplianceStatusFilter] = useState<'ALL' | 'PASS' | 'FAIL' | 'PARTIAL'>('ALL');
  const [complianceFrameworkFilter, setComplianceFrameworkFilter] = useState<string>('ALL');
  const [complianceControls, setComplianceControls] = useState<ComplianceControl[]>([]);
  const [complianceSummary, setComplianceSummary] = useState<any>(null);
  const [complianceSource, setComplianceSource] = useState<'database' | 'evaluated' | 'offline_fallback' | 'no_data'>('no_data');
  const [isLoadingCompliance, setIsLoadingCompliance] = useState(false);

  // SecOps Remediation Console state
  const [isConsoleOpen, setIsConsoleOpen] = useState(false);
  const [consoleInput, setConsoleInput] = useState('');
  const [isConsoleExecuting, setIsConsoleExecuting] = useState(false);
  const [consoleMessages, setConsoleMessages] = useState<SecOpsMessage[]>([
    {
      id: 'init',
      sender: 'system',
      text: 'SecOps Remediation Engine initialized. Continuous posture assessment, TreeSHAP quantitative risk attribution, and zero-trust Infrastructure-as-Code mitigation ready.',
      timestamp: 'Ready'
    }
  ]);

  // Simulation Sliders
  const [simPrivilege, setSimPrivilege] = useState(85);
  const [simExposure, setSimExposure] = useState(90);
  const [simRadius, setSimRadius] = useState(70);
  const [simEncryption, setSimEncryption] = useState(40);

  // Ingestion State (Testing states: idle, loading, complete, error)
  const [uploadStatus, setUploadStatus] = useState<'idle' | 'loading' | 'complete' | 'error'>('idle');
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const [uploadErrorMessage, setUploadErrorMessage] = useState<string | null>(null);
  const [lastIngestionResult, setLastIngestionResult] = useState<IngestionResult | null>(null);
  const [ingestionStats, setIngestionStats] = useState<IngestionStats | null>(null);
  const [rawEvents, setRawEvents] = useState<TelemetryEvent[]>([]);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Telemetry stream (polled from backend)
  const [telemetryLogs, setTelemetryLogs] = useState<Array<{ id: string; time: string; cloud: string; action: string; actor?: string; resource?: string; status: 'WARN' | 'CRIT' | 'INFO' }>>([]);

  // Backend connection state
  const [backendHealth, setBackendHealth] = useState<HealthData>({
    status: 'checking',
    service: 'cloudshield-iq-api',
    version: '0.1.0'
  });
  const [isRefreshing, setIsRefreshing] = useState(false);

  const checkBackendHealth = async () => {
    setIsRefreshing(true);
    try {
      const data = await apiCheckBackendHealth();
      setBackendHealth(data);
    } catch {
      setBackendHealth({
        status: 'offline',
        service: 'cloudshield-iq-api',
        version: '0.1.0',
        timestamp: new Date().toLocaleTimeString(),
        error: 'Offline'
      });
    } finally {
      setIsRefreshing(false);
    }
  };

  const [modelInfo, setModelInfo] = useState<{
    model_version: string;
    algorithm: string;
    is_trained: boolean;
    trained_at?: string;
    training_records_count: number;
    feature_count: number;
    features: string[];
    contamination: number;
    n_estimators: number;
    status: string;
    metrics?: Record<string, any>;
  } | null>(null);

  const [mlInferenceResult, setMlInferenceResult] = useState<any>(null);
  const [isInferring, setIsInferring] = useState(false);

  const fetchModelInfo = async () => {
    try {
      const data = await apiFetchModelInfo();
      setModelInfo(data);
    } catch {
      // Offline fallback
    }
  };

  const [supervisedModelInfo, setSupervisedModelInfo] = useState<{
    model_version: string;
    algorithm: string;
    is_trained: boolean;
    created_at?: string;
    training_records_count: number;
    feature_count: number;
    classes: string[];
    status: string;
    metrics?: Record<string, any>;
  } | null>(null);

  const [supervisedRiskResult, setSupervisedRiskResult] = useState<any>(null);
  const [isSupervisedInferring, setIsSupervisedInferring] = useState(false);

  // Phase 7: TreeSHAP Explainability State
  const [globalShapAttributions, setGlobalShapAttributions] = useState<{
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
  } | null>(null);

  const [selectedEventExplanation, setSelectedEventExplanation] = useState<{
    event_id?: string;
    base_value: number;
    predicted_risk_score: number;
    top_risk_drivers: Array<{
      feature_name: string;
      display_name: string;
      domain: string;
      shap_value: number;
      feature_value: any;
      direction: string;
      description: string;
    }>;
    top_risk_mitigators: Array<{
      feature_name: string;
      display_name: string;
      domain: string;
      shap_value: number;
      feature_value: any;
      direction: string;
      description: string;
    }>;
    all_attributions: Record<string, number>;
  } | null>(null);

  const [isExplainingEvent, setIsExplainingEvent] = useState(false);

  // Grounded LLM Explanation Layer State
  const [selectedFindingExplanation, setSelectedFindingExplanation] = useState<SecurityExplanation | null>(null);
  const [isLoadingExplanation, setIsLoadingExplanation] = useState(false);
  const [explanationError, setExplanationError] = useState<string | null>(null);

  const fetchExplanationForFinding = async (finding: Finding) => {
    setIsLoadingExplanation(true);
    setExplanationError(null);
    try {
      const data = await apiExplainFinding(finding.id);
      setSelectedFindingExplanation(data);
    } catch {
      setSelectedFindingExplanation(null);
      setExplanationError('Backend explanation service unavailable for this finding.');
    } finally {
      setIsLoadingExplanation(false);
    }
  };

  useEffect(() => {
    if (selectedFinding) {
      fetchExplanationForFinding(selectedFinding);
    }
  }, [selectedFinding?.id]);

  const fetchSupervisedModelInfo = async () => {
    try {
      const data = await apiFetchRiskModelInfo();
      setSupervisedModelInfo(data);
    } catch {
      // Offline fallback
    }
  };

  const fetchGlobalShapAttributions = async () => {
    try {
      const data = await apiFetchGlobalShapAttributions(6);
      setGlobalShapAttributions(data);
    } catch {
      setGlobalShapAttributions(null);
    }
  };

  const explainEventWithShap = async (eventPayload?: any) => {
    const event = eventPayload || (rawEvents.length > 0 ? rawEvents[0] : null);
    if (!event) {
      showToast('No telemetry event available for TreeSHAP analysis. Ingest telemetry first.', 'warn');
      return;
    }
    setIsExplainingEvent(true);
    try {
      const data = await apiExplainEventWithShap(event, 4);
      setSelectedEventExplanation(data);
    } catch (err: any) {
      setSelectedEventExplanation(null);
      showToast(`TreeSHAP calculation failed: ${err.message || 'Service unavailable'}`, 'warn');
    } finally {
      setIsExplainingEvent(false);
    }
  };

  const runLiveSupervisedScan = async () => {
    if (rawEvents.length === 0) {
      showToast('Ingest telemetry before running ML inference.', 'warn');
      return;
    }
    setIsSupervisedInferring(true);
    try {
      const eventsToScore = rawEvents.slice(0, 10).map(e => ({
        event_id: e.event_id,
        timestamp: e.timestamp,
        cloud_provider: e.cloud_provider,
        resource_type: e.resource_type,
        action: e.raw_action || e.canonical_action,
        actor_type: e.actor_type,
        actor_name: e.actor_name,
        source_ip: e.source_ip,
        mfa_used: e.mfa_used,
        outcome: e.outcome,
      }));

      const data = await apiTriggerLiveRiskScan(eventsToScore);
      setSupervisedRiskResult(data);
    } catch (err: any) {
      setSupervisedRiskResult(null);
      showToast(`Supervised scan failed: ${err.message || 'Service unavailable'}`, 'warn');
    } finally {
      setIsSupervisedInferring(false);
    }
  };

  const runLiveMlInference = async () => {
    if (rawEvents.length === 0) {
      showToast('Ingest telemetry before running ML inference.', 'warn');
      return;
    }
    setIsInferring(true);
    try {
      const eventsToDetect = rawEvents.slice(0, 10).map(e => ({
        event_id: e.event_id,
        timestamp: e.timestamp,
        cloud_provider: e.cloud_provider,
        resource_type: e.resource_type,
        action: e.raw_action || e.canonical_action,
        actor_type: e.actor_type,
        actor_name: e.actor_name,
        source_ip: e.source_ip,
        mfa_used: e.mfa_used,
        outcome: e.outcome,
      }));

      const data = await apiTriggerAnomalyDetection(eventsToDetect);
      setMlInferenceResult(data);
    } catch (err: any) {
      setMlInferenceResult(null);
      showToast(`Anomaly detection failed: ${err.message || 'Service unavailable'}`, 'warn');
    } finally {
      setIsInferring(false);
    }
  };

  // Centralized Data Loaders
  const loadFindings = async () => {
    setIsLoadingFindings(true);
    try {
      const data = await apiFetchFindings({ includeFallback: false });
      if (data.findings && data.findings.length > 0) {
        setFindings(data.findings);
        setFindingsSource((data.data_source as any) || 'database');
        const statusMap: Record<string, 'OPEN' | 'IN_PROGRESS' | 'RESOLVED'> = {};
        data.findings.forEach(f => {
          statusMap[f.id] = (f.status as any) || 'OPEN';
        });
        setFindingStatuses(statusMap);
        setSelectedFinding(prev => {
          if (prev && data.findings.some(f => f.id === prev.id)) return prev;
          return data.findings[0];
        });
      } else {
        setFindings([]);
        setFindingsSource(data.data_source === 'offline_fallback' ? 'offline_fallback' : 'empty');
        setSelectedFinding(null);
      }
    } catch {
      setFindings([]);
      setFindingsSource('empty');
      setSelectedFinding(null);
    } finally {
      setIsLoadingFindings(false);
    }
  };

  const handleFindingStatusUpdate = async (findingId: string, newStatus: 'OPEN' | 'IN_PROGRESS' | 'RESOLVED') => {
    try {
      const res = await apiUpdateFindingStatus(findingId, newStatus);
      setFindingStatuses(prev => ({ ...prev, [findingId]: res.status as any }));
      setFindings(prev => prev.map(f => f.id === findingId ? { ...f, status: res.status as any } : f));
      if (selectedFinding && selectedFinding.id === findingId) {
        setSelectedFinding(prev => prev ? { ...prev, status: res.status as any } : null);
      }
      showToast(`${findingId} status updated to ${newStatus.replace('_', ' ')}`, 'success');
    } catch (err: any) {
      showToast(`Failed to update status: ${err.message || 'Error'}`, 'warn');
    }
  };

  const loadCompliance = async () => {
    setIsLoadingCompliance(true);
    try {
      const evalData = await apiFetchComplianceEvaluations();
      if (evalData && evalData.results && evalData.results.length > 0) {
        setComplianceControls(evalData.results as any);
        setComplianceSummary(evalData.summary);
        setComplianceSource('evaluated');
      } else {
        setComplianceControls([]);
        setComplianceSummary(evalData?.summary || null);
        setComplianceSource('no_data');
      }
    } catch {
      setComplianceControls([]);
      setComplianceSummary(null);
      setComplianceSource('no_data');
    } finally {
      setIsLoadingCompliance(false);
    }
  };

  const loadTelemetry = async () => {
    try {
      const data = await apiFetchIngestedEvents(30);
      const events = data.events || [];
      setRawEvents(events);
      if (events.length > 0) {
        const mapped = events.map((e, idx) => ({
          id: e.event_id || `EVT-${idx}`,
          time: e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : 'Recent',
          cloud: (e.cloud_provider || 'AWS').toUpperCase(),
          action: e.raw_action || e.canonical_action || 'Access',
          actor: e.actor_name,
          resource: e.resource_id,
          status: (
            e.outcome?.toUpperCase() === 'FAILURE' ? 'CRIT' :
            (e.raw_action?.toLowerCase().includes('delete') || e.raw_action?.toLowerCase().includes('stop') || e.raw_action?.toLowerCase().includes('putbucket') ? 'WARN' : 'INFO')
          ) as 'WARN' | 'CRIT' | 'INFO',
        }));
        setTelemetryLogs(mapped);
      } else {
        setTelemetryLogs([]);
      }
    } catch {
      // Offline
    }
  };

  const loadStats = async () => {
    try {
      const stats = await apiFetchIngestionStats();
      setIngestionStats(stats);
    } catch {
      // offline
    }
  };

  const refreshDashboardData = async () => {
    await Promise.allSettled([
      checkBackendHealth(),
      loadFindings(),
      loadCompliance(),
      loadTelemetry(),
      loadStats(),
      fetchModelInfo(),
      fetchSupervisedModelInfo(),
      fetchGlobalShapAttributions(),
    ]);
  };

  // Initial mount load
  useEffect(() => {
    refreshDashboardData();
    const interval = setInterval(() => {
      checkBackendHealth();
      loadStats();
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  // Keyboard shortcut listener for Command Palette (Ctrl+K / ⌘K)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsCommandPaletteOpen(prev => !prev);
      } else if (e.key === 'Escape') {
        setIsCommandPaletteOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Realtime UTC Chronometer Ticker (ticks every second)
  useEffect(() => {
    const timer = setInterval(() => {
      setUtcTime(new Date().toUTCString().replace('GMT', 'UTC'));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Telemetry event stream polling (controlled by isLiveStreamActive)
  useEffect(() => {
    if (!isLiveStreamActive) return;
    loadTelemetry();
    const timer = setInterval(() => {
      loadTelemetry();
    }, 5000);

    return () => clearInterval(timer);
  }, [isLiveStreamActive]);

  const copyToClipboard = (text: string, key: string, label: string = 'Copied to clipboard') => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    showToast(label, 'success');
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleExportComplianceReport = async () => {
    try {
      const report = await apiFetchComplianceReport();
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `compliance-audit-report-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast('Live Compliance Audit Report (JSON) exported from backend', 'success');
    } catch {
      const reportData = {
        report_id: `COMP-AUDIT-${Date.now()}`,
        generated_at: new Date().toISOString(),
        overall_compliance_score_percent: complianceSummary?.overall_pass_rate ?? 0,
        data_source: complianceSource,
        total_controls: complianceControls.length,
        passing_controls: complianceControls.filter(c => c.status === 'PASS').length,
        failing_controls: complianceControls.filter(c => c.status === 'FAIL').length,
        partial_controls: complianceControls.filter(c => c.status === 'PARTIAL').length,
        evaluated_frameworks: frameworkCards.map(f => f.name),
        controls: complianceControls
      };
      const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `compliance-audit-report-offline-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast('Compliance Audit Report (Offline Fallback) exported', 'warn');
    }
  };

  const handleExecutePlaybook = (promptText?: string) => {
    const query = promptText || consoleInput;
    if (!query.trim()) return;

    toastSeqRef.current += 1;
    const operatorMsg: SecOpsMessage = {
      id: `${Date.now()}-${toastSeqRef.current}`,
      sender: 'operator',
      text: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setConsoleMessages(prev => [...prev, operatorMsg]);
    setConsoleInput('');
    setIsConsoleExecuting(true);
    setIsConsoleOpen(true);

    setTimeout(() => {
      let sysResponse = '';
      let snippet = '';

      if (selectedFinding) {
        sysResponse = `Remediation Plan for ${selectedFinding.id} [${selectedFinding.severity}]: ${selectedFinding.remediation}`;
        snippet = selectedFinding.cliCommand || selectedFinding.terraform || '# Non-destructive inspection\naws securityhub get-findings';
      } else if (findings.length > 0) {
        const top = findings[0];
        sysResponse = `Remediation Plan for top finding ${top.id} [${top.severity}]: ${top.remediation}`;
        snippet = top.cliCommand || top.terraform || '# Non-destructive inspection\naws securityhub get-findings';
      } else {
        sysResponse = 'No security finding selected or ingested. Select a finding from the Findings tab to inspect its non-destructive remediation playbooks.';
        snippet = '# No ingested finding available';
      }

      toastSeqRef.current += 1;
      setConsoleMessages(prev => [
        ...prev,
        {
          id: `${Date.now()}-${toastSeqRef.current}`,
          sender: 'system',
          text: sysResponse,
          code: snippet,
          codeLang: snippet.includes('resource') ? 'terraform' : 'bash',
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
      setIsConsoleExecuting(false);
    }, 300);
  };

  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      const matchesCloud = selectedCloudFilter === 'ALL' || f.cloud === selectedCloudFilter;
      const matchesSeverity = selectedSeverityFilter === 'ALL' || f.severity === selectedSeverityFilter;
      const matchesCategory = selectedCategoryFilter === 'ALL' || f.category === selectedCategoryFilter;
      const matchesSearch = f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.resourceId.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.id.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesCloud && matchesSeverity && matchesCategory && matchesSearch;
    });
  }, [findings, selectedCloudFilter, selectedSeverityFilter, selectedCategoryFilter, searchQuery]);

  const filteredComplianceControls = useMemo(() => {
    return complianceControls.filter(c => {
      const matchesStatus = complianceStatusFilter === 'ALL' || c.status === complianceStatusFilter;
      const matchesFramework = complianceFrameworkFilter === 'ALL' || c.framework === complianceFrameworkFilter;
      return matchesStatus && matchesFramework;
    });
  }, [complianceControls, complianceStatusFilter, complianceFrameworkFilter]);

  const filteredTelemetryLogs = useMemo(() => {
    return telemetryLogs.filter(log => {
      if (telemetryFilter === 'ALL') return true;
      if (telemetryFilter === 'CRIT') return log.status === 'CRIT';
      return log.cloud.toUpperCase() === telemetryFilter.toUpperCase();
    });
  }, [telemetryLogs, telemetryFilter]);

  const simulatedScore = Math.min(100, Math.round((simPrivilege * 0.35) + (simExposure * 0.35) + (simRadius * 0.2) + (simEncryption * 0.1)));

  // Real dataset upload handler
  const handleRealFileUpload = async (file: File) => {
    setUploadStatus('loading');
    setUploadedFileName(file.name);
    setUploadErrorMessage(null);
    try {
      const result = await apiUploadTelemetryFile(file);
      setLastIngestionResult(result);
      setUploadStatus('complete');
      showToast(`Successfully ingested ${file.name} (${result.successful_events} events, ${result.risk_summary.findings_count} findings)`, 'success');
      await Promise.all([loadFindings(), loadCompliance(), loadTelemetry(), loadStats(), fetchGlobalShapAttributions()]);
    } catch (err: any) {
      setUploadStatus('error');
      setUploadErrorMessage(err.message || 'File upload failed');
      showToast(`Upload failed: ${err.message}`, 'warn');
    }
  };

  // Benchmark dataset loader handler
  const handleLoadSampleBenchmark = async (sampleType: string) => {
    setUploadStatus('loading');
    const sampleNames: Record<string, string> = {
      cloudtrail: 'aws_cloudtrail_events.json',
      azure: 'azure_activity_events.json',
      gcp: 'gcp_audit_events.json',
      attack_scenario: 'multi_stage_attack_scenario.json',
      synthetic: 'cloud_security_events.csv',
    };
    const fname = sampleNames[sampleType] || `${sampleType}.json`;
    setUploadedFileName(fname);
    setUploadErrorMessage(null);
    try {
      const result = await apiLoadSampleBenchmark(sampleType);
      setLastIngestionResult(result);
      setUploadStatus('complete');
      showToast(`Loaded ${fname} (${result.successful_events} events, ${result.risk_summary.findings_count} findings)`, 'success');
      await Promise.all([loadFindings(), loadCompliance(), loadTelemetry(), loadStats(), fetchGlobalShapAttributions()]);
    } catch (err: any) {
      setUploadStatus('error');
      setUploadErrorMessage(err.message || 'Benchmark ingestion failed');
      showToast(`Ingestion failed: ${err.message}`, 'warn');
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleRealFileUpload(e.target.files[0]);
    }
  };

  const handleUploadButtonClick = () => {
    if (fileInputRef.current?.files && fileInputRef.current.files.length > 0) {
      handleRealFileUpload(fileInputRef.current.files[0]);
    } else {
      showToast('Please select a CSV or JSON dataset first.', 'warn');
      fileInputRef.current?.click();
    }
  };

  const frameworkCards = useMemo(() => {
    if (complianceSummary?.framework_scores && Object.keys(complianceSummary.framework_scores).length > 0) {
      return Object.entries(complianceSummary.framework_scores).map(([name, pct]: [string, any]) => {
        const controlsForFw = complianceControls.filter(c => c.framework === name);
        const pass = controlsForFw.filter(c => c.status === 'PASS').length;
        const total = controlsForFw.length || 1;
        const numPct = typeof pct === 'number' ? Math.round(pct) : Math.round((pass / total) * 100);
        return {
          name,
          pass,
          fail: total - pass,
          total,
          score: `${numPct}%`,
          pct: numPct
        };
      });
    }

    const fwMap: Record<string, { pass: number; fail: number; total: number }> = {};
    complianceControls.forEach(ctrl => {
      const fw = ctrl.framework || 'General';
      if (!fwMap[fw]) fwMap[fw] = { pass: 0, fail: 0, total: 0 };
      fwMap[fw].total += 1;
      if (ctrl.status === 'PASS') fwMap[fw].pass += 1;
      else fwMap[fw].fail += 1;
    });

    if (Object.keys(fwMap).length > 0) {
      return Object.entries(fwMap).map(([name, d]) => {
        const pct = d.total > 0 ? Math.round((d.pass / d.total) * 100) : 0;
        return {
          name,
          pass: d.pass,
          fail: d.fail,
          total: d.total,
          score: `${pct}%`,
          pct
        };
      });
    }

    return [];
  }, [complianceSummary, complianceControls]);

  const auditedAssetsCount = useMemo(() => {
    if (ingestionStats?.total_events_ingested) return ingestionStats.total_events_ingested;
    if (findings.length > 0) {
      const uniqueResources = new Set(findings.map(f => f.resourceId).filter(Boolean));
      return uniqueResources.size || findings.length * 3;
    }
    return 0;
  }, [ingestionStats, findings]);

  const detectedAttckTechniques = useMemo(() => {
    if (findings.length === 0) return [];
    const techMap = new Map<string, { id: string; name: string; desc: string; severity: string }>();
    findings.forEach(f => {
      const cat = (f.category || '').toUpperCase();
      if (cat.includes('IAM') && !techMap.has('T1078.004')) {
        techMap.set('T1078.004', { id: 'T1078.004', name: 'Valid Cloud Accounts', desc: f.title, severity: f.severity });
      } else if (cat.includes('STORAGE') && !techMap.has('T1537')) {
        techMap.set('T1537', { id: 'T1537', name: 'Transfer Data to Cloud Account', desc: f.title, severity: f.severity });
      } else if (cat.includes('NETWORK') && !techMap.has('T1021.004')) {
        techMap.set('T1021.004', { id: 'T1021.004', name: 'SSH Remote Services', desc: f.title, severity: f.severity });
      } else if (cat.includes('LOGGING') && !techMap.has('T1562.001')) {
        techMap.set('T1562.001', { id: 'T1562.001', name: 'Impair Defenses: Disable Cloud Logs', desc: f.title, severity: f.severity });
      } else if (cat.includes('ENCRYPTION') && !techMap.has('T1486')) {
        techMap.set('T1486', { id: 'T1486', name: 'Data Encrypted for Impact / Key Tampering', desc: f.title, severity: f.severity });
      }
    });
    return Array.from(techMap.values());
  }, [findings]);

  const avgRiskScore = useMemo(() => {
    if (findings.length === 0) return 0;
    const sum = findings.reduce((acc, f) => acc + (f.riskScore || 0), 0);
    return Math.round((sum / findings.length) * 10) / 10;
  }, [findings]);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* ═══════════════════════════════════
          NAVIGATION BAR
          ═══════════════════════════════════ */}
      <header className="nav-header">
        <div className="nav-wrapper">
          {/* Logo Left */}
          <a href="#" className="nav-logo-group" onClick={(e) => { e.preventDefault(); setActiveTab('overview'); }}>
            <span className="nav-logo-badge">CS</span>
            <span className="nav-logo-text">CloudShield IQ</span>
          </a>

          {/* Nav Links Center (Desktop) */}
          <nav className="nav-tabs-desktop" aria-label="Main Navigation">
            <button
              className={`nav-tab-btn ${activeTab === 'overview' ? 'is-active' : ''}`}
              onClick={() => setActiveTab('overview')}
            >
              Overview
            </button>
            <button
              className={`nav-tab-btn ${activeTab === 'findings' ? 'is-active' : ''}`}
              onClick={() => setActiveTab('findings')}
            >
              Findings ({findings.length})
            </button>
            <button
              className={`nav-tab-btn ${activeTab === 'compliance' ? 'is-active' : ''}`}
              onClick={() => setActiveTab('compliance')}
            >
              Compliance
            </button>
            <button
              className={`nav-tab-btn ${activeTab === 'ml-engine' ? 'is-active' : ''}`}
              onClick={() => setActiveTab('ml-engine')}
            >
              ML Engine
            </button>
            <button
              className={`nav-tab-btn ${activeTab === 'ingestion' ? 'is-active' : ''}`}
              onClick={() => setActiveTab('ingestion')}
            >
              Ingestion
            </button>
            <button
              className={`nav-tab-btn ${activeTab === 'architecture' ? 'is-active' : ''}`}
              onClick={() => setActiveTab('architecture')}
            >
              Architecture
            </button>
          </nav>

          {/* Controls & CTA Right */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button
              className="btn btn-secondary"
              onClick={refreshDashboardData}
              title="Refresh all backend data and sync with database"
              aria-label="Refresh Backend"
            >
              <RefreshCw size={16} className={isRefreshing ? 'spinner' : ''} />
              <span className="caption" style={{ color: backendHealth.status === 'ok' ? 'var(--status-pass)' : 'var(--text-secondary)' }}>
                {backendHealth.status === 'ok' ? (
                  findingsSource === 'database' ? 'API Online (DB)' : 'API Online'
                ) : 'API Standalone'}
              </span>
            </button>

            <button
              className="btn btn-primary"
              onClick={() => setIsConsoleOpen(true)}
              aria-label="Open SecOps Console"
            >
              <Terminal size={15} />
              <span>SecOps Console</span>
            </button>

            {/* Mobile Hamburger Button */}
            <button
              className="hamburger-btn"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              aria-label="Toggle mobile menu"
            >
              {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
          </div>
        </div>

        {/* Mobile Navigation Drawer */}
        <div className={`mobile-nav-drawer ${mobileMenuOpen ? 'is-open' : ''}`}>
          {(['overview', 'findings', 'compliance', 'ml-engine', 'ingestion', 'architecture'] as const).map(tab => (
            <button
              key={tab}
              className={`mobile-nav-item ${activeTab === tab ? 'is-active' : ''}`}
              onClick={() => {
                setActiveTab(tab);
                setMobileMenuOpen(false);
              }}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1).replace('-', ' ')}
            </button>
          ))}
        </div>
      </header>

      {/* ═══════════════════════════════════
          TACTICAL OPERATIONS HUD / TICKER
          ═══════════════════════════════════ */}
      <div className="hud-ticker">
        <div className="hud-ticker-inner">
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
            <span className="hud-item">
              <span className="hud-pulse-dot" />
              <span style={{ color: 'var(--accent)', fontWeight: 700 }}>ASSESSED POSTURE</span>
            </span>
            <span className="hud-item" style={{ color: 'var(--text-primary)' }}>
              UTC {utcTime}
            </span>
            <span className="hud-item">
              <span style={{ color: 'var(--text-secondary)' }}>Threat Level:</span>
              <span className="tag tag-critical" style={{ fontSize: '10px' }}>DEFCON 2 / ELEVATED</span>
            </span>
            <span className="hud-item">
              <span style={{ color: 'var(--text-secondary)' }}>Tenants:</span>
              <span className="tag" style={{ fontSize: '10px' }}>AWS us-east-1</span>
              <span className="tag" style={{ fontSize: '10px' }}>Azure eastus</span>
              <span className="tag" style={{ fontSize: '10px' }}>GCP us-central1</span>
            </span>
            <span className="hud-item">
              <span style={{ color: 'var(--text-secondary)' }}>Source:</span>
              <span
                className={`tag ${
                  findingsSource === 'database' ? 'tag-pass' :
                  findingsSource === 'ingested_memory' ? 'badge-blue' :
                  findingsSource === 'offline_fallback' ? 'tag-warning' : ''
                }`}
                style={{ fontSize: '10px', fontWeight: 700 }}
              >
                {findingsSource === 'database' ? '● REAL DATABASE DATA' :
                 findingsSource === 'ingested_memory' ? '● INGESTED STREAM' :
                 findingsSource === 'offline_fallback' ? '▲ OFFLINE FALLBACK DATA' : '○ NO DATA'}
              </span>
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button
              className="hud-search-btn"
              onClick={() => setIsCommandPaletteOpen(true)}
              title="Search Findings, Controls & Models (Ctrl+K)"
            >
              <Search size={12} />
              <span>Quick Search</span>
              <kbd style={{ fontSize: '9px', background: 'var(--bg-primary)', padding: '1px 4px', borderRadius: '2px', border: '1px solid var(--border)' }}>⌘K</kbd>
            </button>
          </div>
        </div>
      </div>

      {/* ═══════════════════════════════════
          TOAST NOTIFICATION OVERLAY
          ═══════════════════════════════════ */}
      {toasts.length > 0 && (
        <div className="toast-container">
          {toasts.map(t => (
            <div key={t.id} className="toast-item">
              {t.type === 'success' ? (
                <CheckCircle2 size={16} style={{ color: 'var(--accent)' }} />
              ) : t.type === 'warn' ? (
                <AlertTriangle size={16} style={{ color: 'var(--status-warning)' }} />
              ) : (
                <Activity size={16} style={{ color: 'var(--text-secondary)' }} />
              )}
              <span>{t.message}</span>
            </div>
          ))}
        </div>
      )}

      {/* ═══════════════════════════════════
          COMMAND PALETTE MODAL (Ctrl+K)
          ═══════════════════════════════════ */}
      {isCommandPaletteOpen && (
        <div className="cmd-palette-backdrop" onClick={() => setIsCommandPaletteOpen(false)}>
          <div className="cmd-palette-box" onClick={e => e.stopPropagation()}>
            <input
              type="text"
              className="cmd-palette-input"
              placeholder="Type to search findings, compliance controls, or ML tools... (ESC to close)"
              value={paletteQuery}
              onChange={e => setPaletteQuery(e.target.value)}
              autoFocus
            />
            <div className="cmd-palette-results">
              <div className="caption" style={{ padding: '4px 8px', color: 'var(--text-muted)' }}>
                FINDINGS & INCIDENTS
              </div>
              {findings
                .filter(f => f.title.toLowerCase().includes(paletteQuery.toLowerCase()) || f.id.toLowerCase().includes(paletteQuery.toLowerCase()))
                .slice(0, 4)
                .map(f => (
                  <button
                    key={f.id}
                    className="cmd-palette-item"
                    onClick={() => {
                      setSelectedFinding(f);
                      setActiveTab('findings');
                      setIsCommandPaletteOpen(false);
                      showToast(`Navigated to ${f.id}`);
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600 }}>{f.id}: {f.title}</div>
                      <div className="caption">{f.cloud} • {f.category} • Risk Score {f.riskScore}</div>
                    </div>
                    <span className={`tag ${f.severity === 'CRITICAL' ? 'tag-critical' : 'tag-warning'}`}>
                      {f.severity}
                    </span>
                  </button>
                ))}

              <div className="caption" style={{ padding: '8px 8px 4px', color: 'var(--text-muted)' }}>
                SYSTEM CONTROLS & ENGINES
              </div>
              <button
                className="cmd-palette-item"
                onClick={() => {
                  setActiveTab('ml-engine');
                  setIsCommandPaletteOpen(false);
                }}
              >
                <div>
                  <div style={{ fontWeight: 600 }}>TreeSHAP Explainability & Waterfall Engine</div>
                  <div className="caption">Inspect mathematical local & global risk attributions</div>
                </div>
                <span className="tag tag-accent">PHASE 7</span>
              </button>
              <button
                className="cmd-palette-item"
                onClick={() => {
                  setActiveTab('compliance');
                  setIsCommandPaletteOpen(false);
                }}
              >
                <div>
                  <div style={{ fontWeight: 600 }}>Multi-Cloud Compliance Matrix</div>
                  <div className="caption">Audit CIS AWS 1.4, NIST 800-53, PCI-DSS 4.0 controls</div>
                </div>
                <span className="tag">6 FRAMEWORKS</span>
              </button>
              <button
                className="cmd-palette-item"
                onClick={() => {
                  setIsConsoleOpen(true);
                  setIsCommandPaletteOpen(false);
                }}
              >
                <div>
                  <div style={{ fontWeight: 600 }}>SecOps Interactive Remediation Console</div>
                  <div className="caption">Execute direct zero-trust playbooks</div>
                </div>
                <span className="tag">CLI</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════
          MAIN APPLICATION CONTENT
          ═══════════════════════════════════ */}
      <main className="app-container" style={{ flexGrow: 1, paddingBottom: '64px' }}>
        {/* HERO SECTION — Elevated Executive Banner on Overview; Sleek Context Strip on Deep Tabs */}
        {activeTab === 'overview' ? (
          <section style={{ paddingTop: '32px', paddingBottom: '28px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="badge-emerald"><Shield size={12} /> Version 0.1.0</span>
                <span className="caption text-emerald-400">Multi-Cloud Security & Compliance Suite</span>
              </div>
              <h1>CloudShield IQ</h1>
              <p style={{ maxWidth: '820px', fontSize: '15px', color: 'var(--text-secondary)' }}>
                Continuous multi-cloud posture evaluation, quantitative TreeSHAP risk attribution, and automated zero-trust remediation across AWS, Azure, and GCP.
              </p>
            </div>

            {/* Above the fold CTA bar */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', marginTop: '20px' }}>
              <button
                className="btn btn-primary"
                onClick={() => setActiveTab('findings')}
              >
                <ShieldAlert size={15} />
                <span>Audit Security Findings</span>
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => setActiveTab('compliance')}
              >
                <Layers size={15} />
                <span>View Compliance Matrix</span>
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => handleExecutePlaybook('Inspect remediation playbooks for active findings')}
              >
                <Terminal size={15} />
                <span>Inspect Remediation Playbook</span>
              </button>
            </div>
          </section>
        ) : (
          <div style={{ padding: '20px 0 16px 0', borderBottom: '1px solid var(--border-subtle)', marginBottom: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h1 style={{ display: 'none' }}>CloudShield IQ</h1>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="badge-emerald" style={{ fontSize: '10px' }}>
                  <Shield size={11} /> CloudShield IQ
                </span>
                <span style={{ color: 'var(--text-muted)' }}>/</span>
                <span style={{ color: 'var(--text-primary)', fontWeight: 600, fontSize: '15px' }}>
                  {activeTab === 'findings' ? 'Security Findings Workspace' :
                   activeTab === 'compliance' ? 'Compliance Posture & Frameworks' :
                   activeTab === 'ml-engine' ? 'Machine Learning Risk Intelligence' :
                   activeTab === 'ingestion' ? 'Configuration & Telemetry Ingestion' : 'System Architecture Topology'}
                </span>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <button
                className="btn btn-secondary"
                style={{ height: '32px', minHeight: '32px', padding: '0 10px', fontSize: '12px' }}
                onClick={() => setActiveTab('overview')}
              >
                Return to Overview
              </button>
            </div>
          </div>
        )}

        {/* ═══════════════════════════════════
            KEY METRICS GRID (Executive Overview)
            ═══════════════════════════════════ */}
        {activeTab === 'overview' && (
          <section style={{ marginBottom: '36px' }}>
            <div className="grid-metrics">
              <div
                className="surface-card kpi-card"
                onClick={() => setActiveTab('ingestion')}
                title="Click to view Ingestion & Asset Telemetry"
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div style={{ width: '28px', height: '28px', borderRadius: '6px', backgroundColor: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <Server size={14} style={{ color: 'var(--accent)' }} />
                    </div>
                    <span className="caption">Audited Cloud Assets</span>
                  </div>
                  <span className="kpi-trend-chip" style={{ color: 'var(--status-pass)' }}>
                    {findingsSource === 'database' ? 'DB Active' : findingsSource === 'ingested_memory' ? 'Stream' : 'Fallback'}
                  </span>
                </div>
                <div className="h1" style={{ marginTop: '12px' }}>{auditedAssetsCount}</div>
                <div className="caption" style={{ marginTop: '4px' }}>
                  {ingestionStats?.total_events_ingested ? `${ingestionStats.total_events_ingested} normalized events` : 'Across connected cloud tenants'}
                </div>
                <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '999px', marginTop: '12px', overflow: 'hidden' }}>
                  <div style={{ width: `${Math.min(100, Math.max(15, auditedAssetsCount))}%`, height: '100%', backgroundColor: 'var(--accent)' }} />
                </div>
              </div>

              <div
                className="surface-card kpi-card"
                onClick={() => setActiveTab('ml-engine')}
                title="Click to inspect ML Risk Engine"
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div style={{ width: '28px', height: '28px', borderRadius: '6px', backgroundColor: 'rgba(239, 68, 68, 0.12)', border: '1px solid rgba(239, 68, 68, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <ShieldAlert size={14} style={{ color: avgRiskScore >= 70 ? 'var(--status-critical)' : 'var(--status-warning)' }} />
                    </div>
                    <span className="caption">Composite Risk Score</span>
                  </div>
                  <span className="kpi-trend-chip" style={{ color: avgRiskScore >= 70 ? 'var(--status-critical)' : avgRiskScore >= 50 ? 'var(--status-warning)' : 'var(--status-pass)' }}>
                    {avgRiskScore >= 70 ? 'CRITICAL' : avgRiskScore >= 50 ? 'ELEVATED' : avgRiskScore > 0 ? 'NOMINAL' : 'CLEAR'}
                  </span>
                </div>
                <div className="h1" style={{ marginTop: '12px', color: avgRiskScore >= 70 ? 'var(--status-critical)' : avgRiskScore >= 50 ? 'var(--status-warning)' : 'var(--status-pass)' }}>
                  {avgRiskScore.toFixed(1)} / 100
                </div>
                <div className="caption" style={{ marginTop: '4px' }}>
                  {avgRiskScore >= 70 ? 'High risk exposure detected' : avgRiskScore >= 50 ? 'Moderate exposure detected' : 'Baseline security posture'}
                </div>
                <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '999px', marginTop: '12px', overflow: 'hidden' }}>
                  <div style={{ width: `${Math.min(100, avgRiskScore)}%`, height: '100%', backgroundColor: avgRiskScore >= 70 ? 'var(--status-critical)' : avgRiskScore >= 50 ? 'var(--status-warning)' : 'var(--status-pass)' }} />
                </div>
              </div>

              <div
                className="surface-card kpi-card"
                onClick={() => {
                  setSelectedSeverityFilter('CRITICAL');
                  setActiveTab('findings');
                }}
                title="Click to filter Critical findings"
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div style={{ width: '28px', height: '28px', borderRadius: '6px', backgroundColor: 'rgba(239, 68, 68, 0.12)', border: '1px solid rgba(239, 68, 68, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <AlertTriangle size={14} style={{ color: 'var(--status-critical)' }} />
                    </div>
                    <span className="caption">Critical Findings</span>
                  </div>
                  <span className="kpi-trend-chip" style={{ color: 'var(--status-critical)' }}>Immediate SLA</span>
                </div>
                <div className="h1" style={{ marginTop: '12px', color: 'var(--status-critical)' }}>
                  {findings.filter(f => f.severity === 'CRITICAL').length}
                </div>
                <div className="caption" style={{ marginTop: '4px' }}>Immediate remediation required</div>
                <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '999px', marginTop: '12px', overflow: 'hidden' }}>
                  <div style={{ width: `${Math.min(100, findings.filter(f => f.severity === 'CRITICAL').length * 25)}%`, height: '100%', backgroundColor: 'var(--status-critical)' }} />
                </div>
              </div>

              <div
                className="surface-card kpi-card"
                onClick={() => setActiveTab('compliance')}
                title="Click to view Compliance Matrix"
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div style={{ width: '28px', height: '28px', borderRadius: '6px', backgroundColor: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <CheckCircle2 size={14} style={{ color: 'var(--status-pass)' }} />
                    </div>
                    <span className="caption">Monitored Frameworks</span>
                  </div>
                  <span className="kpi-trend-chip" style={{ color: 'var(--status-pass)' }}>{frameworkCards.length} Active</span>
                </div>
                <div className="h1" style={{ marginTop: '12px' }}>{frameworkCards.length}</div>
                <div className="caption" style={{ marginTop: '4px' }}>
                  {frameworkCards.map(f => f.name.split(' ')[0]).slice(0, 4).join(', ')}
                </div>
                <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '999px', marginTop: '12px', overflow: 'hidden' }}>
                  <div style={{
                    width: `${frameworkCards.reduce((a, b) => a + b.total, 0) > 0 ? Math.round((frameworkCards.reduce((a, b) => a + b.pass, 0) / frameworkCards.reduce((a, b) => a + b.total, 0)) * 100) : 67}%`,
                    height: '100%',
                    backgroundColor: 'var(--status-warning)'
                  }} />
                </div>
              </div>
            </div>
          </section>
        )}

        {/* ═══════════════════════════════════
            TAB 1: POSTURE OVERVIEW
            ═══════════════════════════════════ */}
        {activeTab === 'overview' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
            {/* Multi-Cloud Posture Matrix */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <div>
                  <h3>Multi-Cloud Posture Distribution</h3>
                  <span className="caption">Realtime posture synthesis across connected cloud tenants</span>
                </div>
                <span className="caption">3 Active Cloud Environments</span>
              </div>
              <div className="grid-metrics">
                {/* AWS Card */}
                <div className="surface-card" style={{ borderLeft: '3px solid #FF9900' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 700 }}>AWS Infrastructure</span>
                    <span className={`tag ${findings.filter(f => f.cloud === 'AWS' && f.severity === 'CRITICAL').length > 0 ? 'tag-critical' : findings.filter(f => f.cloud === 'AWS').length > 0 ? 'tag-warning' : 'tag'}`}>
                      {findings.filter(f => f.cloud === 'AWS').length} Findings
                    </span>
                  </div>
                  <div style={{ marginTop: '12px', display: 'flex', justifyContent: 'space-between' }}>
                    <span className="caption">Ingested Events:</span>
                    <span className="code-text"><b>{rawEvents.filter(e => (e.cloud_provider || '').toLowerCase() === 'aws').length}</b> events</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                    <span className="caption">Critical Alerts:</span>
                    <span className="code-text" style={{ color: findings.filter(f => f.cloud === 'AWS' && f.severity === 'CRITICAL').length > 0 ? 'var(--status-critical)' : 'var(--text-secondary)' }}>
                      <b>{findings.filter(f => f.cloud === 'AWS' && f.severity === 'CRITICAL').length} Active</b>
                    </span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                    <span className="caption">CIS AWS 1.4:</span>
                    <span className="code-text"><b>{frameworkCards.find(c => c.name.includes('AWS'))?.score || 'No data'}</b></span>
                  </div>
                  <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '2px', marginTop: '8px', overflow: 'hidden' }}>
                    <div style={{ width: `${frameworkCards.find(c => c.name.includes('AWS'))?.pct || 0}%`, height: '100%', backgroundColor: '#FF9900' }} />
                  </div>
                </div>

                {/* Azure Card */}
                <div className="surface-card" style={{ borderLeft: '3px solid #008AD7' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 700 }}>Azure Infrastructure</span>
                    <span className={`tag ${findings.filter(f => f.cloud === 'Azure' && f.severity === 'CRITICAL').length > 0 ? 'tag-critical' : findings.filter(f => f.cloud === 'Azure').length > 0 ? 'tag-warning' : 'tag'}`}>
                      {findings.filter(f => f.cloud === 'Azure').length} Findings
                    </span>
                  </div>
                  <div style={{ marginTop: '12px', display: 'flex', justifyContent: 'space-between' }}>
                    <span className="caption">Ingested Events:</span>
                    <span className="code-text"><b>{rawEvents.filter(e => (e.cloud_provider || '').toLowerCase() === 'azure').length}</b> events</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                    <span className="caption">Critical Alerts:</span>
                    <span className="code-text" style={{ color: findings.filter(f => f.cloud === 'Azure' && f.severity === 'CRITICAL').length > 0 ? 'var(--status-critical)' : 'var(--text-secondary)' }}>
                      <b>{findings.filter(f => f.cloud === 'Azure' && f.severity === 'CRITICAL').length} Active</b>
                    </span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                    <span className="caption">CIS Azure 2.0:</span>
                    <span className="code-text"><b>{frameworkCards.find(c => c.name.includes('Azure'))?.score || 'No data'}</b></span>
                  </div>
                  <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '2px', marginTop: '8px', overflow: 'hidden' }}>
                    <div style={{ width: `${frameworkCards.find(c => c.name.includes('Azure'))?.pct || 0}%`, height: '100%', backgroundColor: '#008AD7' }} />
                  </div>
                </div>

                {/* GCP Card */}
                <div className="surface-card" style={{ borderLeft: '3px solid #4285F4' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 700 }}>GCP Workloads</span>
                    <span className={`tag ${findings.filter(f => f.cloud === 'GCP' && f.severity === 'CRITICAL').length > 0 ? 'tag-critical' : findings.filter(f => f.cloud === 'GCP').length > 0 ? 'tag-warning' : 'tag'}`}>
                      {findings.filter(f => f.cloud === 'GCP').length} Findings
                    </span>
                  </div>
                  <div style={{ marginTop: '12px', display: 'flex', justifyContent: 'space-between' }}>
                    <span className="caption">Ingested Events:</span>
                    <span className="code-text"><b>{rawEvents.filter(e => (e.cloud_provider || '').toLowerCase() === 'gcp').length}</b> events</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                    <span className="caption">Critical Alerts:</span>
                    <span className="code-text" style={{ color: findings.filter(f => f.cloud === 'GCP' && f.severity === 'CRITICAL').length > 0 ? 'var(--status-critical)' : 'var(--text-secondary)' }}>
                      <b>{findings.filter(f => f.cloud === 'GCP' && f.severity === 'CRITICAL').length} Active</b>
                    </span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                    <span className="caption">CIS GCP 1.3:</span>
                    <span className="code-text"><b>{frameworkCards.find(c => c.name.includes('GCP'))?.score || 'No data'}</b></span>
                  </div>
                  <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '2px', marginTop: '8px', overflow: 'hidden' }}>
                    <div style={{ width: `${frameworkCards.find(c => c.name.includes('GCP'))?.pct || 0}%`, height: '100%', backgroundColor: 'var(--accent)' }} />
                  </div>
                </div>

                {/* Zero-Trust Engine Card */}
                <div className="surface-card" style={{ borderLeft: '3px solid var(--accent)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 700 }}>Zero-Trust Engine</span>
                    <span className="tag tag-accent">{findings.length > 0 ? 'Active' : 'Standby'}</span>
                  </div>
                  <div style={{ marginTop: '12px', display: 'flex', justifyContent: 'space-between' }}>
                    <span className="caption">Available Playbooks:</span>
                    <span className="code-text"><b>{findings.length}</b> Remediations</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                    <span className="caption">Execution Mode:</span>
                    <span className="code-text"><b>Read-Only</b> Safe</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                    <span className="caption">Explainability:</span>
                    <span className="code-text"><b>TreeSHAP</b> {rawEvents.length > 0 ? 'Ready' : 'Pending Ingestion'}</span>
                  </div>
                  <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '2px', marginTop: '8px', overflow: 'hidden' }}>
                    <div style={{ width: `${rawEvents.length > 0 ? 100 : 0}%`, height: '100%', backgroundColor: 'var(--accent)' }} />
                  </div>
                </div>
              </div>
            </div>

            {/* 2-Column: Live Security Telemetry & Risk Severity Breakdown */}
            <div className="grid-2col">
              {/* Telemetry Feed */}
              <div className="surface-card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <h3>Recent Ingested Telemetry</h3>
                    <span className="tag">Backend Event Feed (Polled 5s)</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    {(['ALL', 'AWS', 'AZURE', 'GCP', 'CRIT'] as const).map(flt => (
                      <button
                        key={flt}
                        className={`btn ${telemetryFilter === flt ? 'btn-primary' : 'btn-secondary'}`}
                        style={{ height: '26px', minHeight: '26px', padding: '0 8px', fontSize: '11px' }}
                        onClick={() => setTelemetryFilter(flt)}
                      >
                        {flt}
                      </button>
                    ))}
                    <button
                      className="btn btn-secondary"
                      style={{ height: '26px', minHeight: '26px', padding: '0 8px', fontSize: '11px' }}
                      onClick={() => {
                        setIsLiveStreamActive(!isLiveStreamActive);
                        showToast(isLiveStreamActive ? 'Live telemetry stream paused' : 'Live telemetry stream resumed');
                      }}
                      title={isLiveStreamActive ? 'Pause stream' : 'Resume stream'}
                    >
                      {isLiveStreamActive ? <Pause size={11} /> : <Play size={11} />}
                      <span>{isLiveStreamActive ? 'Pause' : 'Resume'}</span>
                    </button>
                  </div>
                </div>
                <div className="code-snippet-box" style={{ maxHeight: '280px', overflowY: 'auto' }}>
                  {filteredTelemetryLogs.map(log => (
                    <div
                      key={log.id}
                      style={{
                        display: 'grid',
                        gridTemplateColumns: '70px 60px 1fr 50px',
                        gap: '8px',
                        padding: '4px 0',
                        borderBottom: '1px solid var(--border)'
                      }}
                    >
                      <span style={{ color: 'var(--text-secondary)' }}>{log.time}</span>
                      <span style={{ fontWeight: 700 }}>{log.cloud}</span>
                      <span>{log.action}</span>
                      <span style={{
                        color: log.status === 'CRIT' ? 'var(--status-critical)' : log.status === 'WARN' ? 'var(--status-warning)' : 'var(--status-pass)',
                        textAlign: 'right',
                        fontWeight: 700
                      }}>
                        {log.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Risk Distribution Breakdown */}
              <div className="surface-card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h3>Risk Severity Distribution</h3>
                  <span className="tag">{findings.length} Total</span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '8px' }}>
                  {[
                    { label: 'CRITICAL', count: findings.filter(f => f.severity === 'CRITICAL').length, color: 'var(--status-critical)', desc: 'Full account takeover or direct public storage' },
                    { label: 'HIGH', count: findings.filter(f => f.severity === 'HIGH').length, color: 'var(--status-warning)', desc: 'Management port exposed (SSH/RDP) or missing rotation' },
                    { label: 'MEDIUM', count: findings.filter(f => f.severity === 'MEDIUM').length, color: 'var(--text-secondary)', desc: 'Volume default encryption without customer KMS' },
                    { label: 'LOW', count: findings.filter(f => f.severity === 'LOW').length, color: 'var(--text-secondary)', desc: 'Wildcard log permissions with restricted scope' }
                  ].map(item => (
                    <div key={item.label} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontWeight: 700, fontSize: '13px', color: item.color }}>{item.label}</span>
                        <span style={{ fontWeight: 700 }}>{item.count}</span>
                      </div>
                      <div style={{ width: '100%', height: '6px', backgroundColor: 'var(--bg-primary)', borderRadius: '2px', overflow: 'hidden' }}>
                        <div
                          style={{
                            width: `${(item.count / findings.length) * 100}%`,
                            height: '100%',
                            backgroundColor: item.color,
                            borderRadius: '2px'
                          }}
                        />
                      </div>
                      <span className="caption">{item.desc}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* MITRE ATT&CK Defense Matrix Coverage Card */}
            <div className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '8px' }}>
                <div>
                  <h3>MITRE ATT&CK Framework Cloud Matrix</h3>
                  <span className="caption">Active attack techniques mapped from ingested security findings</span>
                </div>
                <span className="tag tag-accent">{detectedAttckTechniques.length} Detected Techniques</span>
              </div>
              {detectedAttckTechniques.length === 0 ? (
                <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-secondary)', border: '1px dashed var(--border)', borderRadius: '4px' }}>
                  ATT&CK mapping unavailable for current dataset (No detected security findings).
                </div>
              ) : (
                <div className="grid-metrics">
                  {detectedAttckTechniques.map(tech => (
                    <div key={tech.id} style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-primary)' }}>
                      <span className={`tag ${tech.severity === 'CRITICAL' ? 'tag-critical' : 'tag-warning'}`}>{tech.id}</span>
                      <div style={{ fontWeight: 700, fontSize: '13px', marginTop: '6px' }}>{tech.name}</div>
                      <p className="caption" style={{ marginTop: '4px' }}>{tech.desc}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Quick Remediation Priority Queue */}
            <div className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '8px' }}>
                <div>
                  <h3>Priority Remediation Queue</h3>
                  <p className="caption" style={{ marginTop: '2px' }}>
                    Findings with highest TreeSHAP risk attribution requiring immediate action
                  </p>
                </div>
                <button className="btn btn-secondary" onClick={() => setActiveTab('findings')}>
                  View All Findings
                </button>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {findings.slice(0, 3).map(f => (
                  <div
                    key={f.id}
                    style={{
                      padding: '16px',
                      border: '1px solid var(--border)',
                      borderRadius: '4px',
                      display: 'flex',
                      flexWrap: 'wrap',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: '12px'
                    }}
                  >
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', maxWidth: '700px' }}>
                      <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <span className={`tag ${f.severity === 'CRITICAL' ? 'tag-critical' : 'tag-warning'}`}>
                          {f.severity}
                        </span>
                        <span className="tag">{f.cloud}</span>
                        <span className="caption code-text">{f.id}</span>
                        <span className="kpi-trend-chip" style={{ color: 'var(--status-critical)' }}>
                          {f.severity === 'CRITICAL' ? 'SLA: Immediate Priority' : 'SLA: Standard Priority'}
                        </span>
                      </div>
                      <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{f.title}</div>
                      <p className="caption">{f.remediation}</p>
                    </div>

                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                      <button
                        className="btn btn-secondary"
                        onClick={() => {
                          setSelectedFinding(f);
                          setActiveTab('findings');
                        }}
                      >
                        Remediate
                      </button>
                      <button
                        className="btn btn-primary"
                        onClick={() => handleExecutePlaybook(`Remediate finding ${f.id} (${f.title})`)}
                      >
                        <Terminal size={14} />
                        <span>Fix in Console</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ═══════════════════════════════════
            TAB 2: SECURITY FINDINGS (MASTER-DETAIL)
            ═══════════════════════════════════ */}
        {activeTab === 'findings' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            {/* Real Data / Persistence Status Banner */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '12px 18px',
                borderRadius: '6px',
                backgroundColor: findingsSource === 'database'
                  ? 'rgba(16, 185, 129, 0.08)'
                  : findingsSource === 'ingested_memory'
                  ? 'rgba(59, 130, 246, 0.08)'
                  : findingsSource === 'offline_fallback'
                  ? 'rgba(245, 158, 11, 0.08)'
                  : 'rgba(100, 116, 139, 0.08)',
                border: `1px solid ${
                  findingsSource === 'database'
                    ? 'rgba(16, 185, 129, 0.3)'
                    : findingsSource === 'ingested_memory'
                    ? 'rgba(59, 130, 246, 0.3)'
                    : findingsSource === 'offline_fallback'
                    ? 'rgba(245, 158, 11, 0.3)'
                    : 'rgba(100, 116, 139, 0.3)'
                }`
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span
                  className={`tag ${
                    findingsSource === 'database' ? 'tag-pass' :
                    findingsSource === 'ingested_memory' ? 'badge-blue' :
                    findingsSource === 'offline_fallback' ? 'tag-warning' : 'tag'
                  }`}
                  style={{ fontWeight: 700 }}
                >
                  {findingsSource === 'database' ? '● REAL DATABASE DATA' :
                   findingsSource === 'ingested_memory' ? '● INGESTED STREAM (IN-MEMORY)' :
                   findingsSource === 'offline_fallback' ? '▲ OFFLINE FALLBACK DATA' : '○ NO INGESTED DATA'}
                </span>
                <span className="caption" style={{ color: 'var(--text-secondary)' }}>
                  {findingsSource === 'database'
                    ? `PostgreSQL repository synchronized. Displaying ${findings.length} findings derived from ingested cloud infrastructure.`
                    : findingsSource === 'ingested_memory'
                    ? `Active telemetry pipeline normalized. Displaying ${findings.length} findings from current session.`
                    : findingsSource === 'offline_fallback'
                    ? 'Backend database is offline or unseeded. Displaying baseline fallback security findings (Read-Only).'
                    : 'No telemetry or findings ingested yet. Use the Ingestion tab to upload a cloud telemetry dump.'}
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <button
                  className="btn btn-secondary"
                  style={{ height: '30px', minHeight: '30px', padding: '0 10px', fontSize: '12px' }}
                  onClick={loadFindings}
                  disabled={isLoadingFindings}
                >
                  <RefreshCw size={13} className={isLoadingFindings ? 'spinner' : ''} />
                  <span>{isLoadingFindings ? 'Refreshing...' : 'Refresh Findings'}</span>
                </button>
              </div>
            </div>

            {/* Filter Bar */}
            <div className="surface-card" style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
                <span className="caption" style={{ marginRight: '4px' }}>Provider:</span>
                {(['ALL', 'AWS', 'Azure', 'GCP'] as const).map(cloud => (
                  <button
                    key={cloud}
                    className={`btn ${selectedCloudFilter === cloud ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ height: '36px', minHeight: '36px', padding: '0 12px' }}
                    onClick={() => setSelectedCloudFilter(cloud)}
                  >
                    {cloud}
                  </button>
                ))}
              </div>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
                <span className="caption" style={{ marginRight: '4px' }}>Severity:</span>
                {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => (
                  <button
                    key={sev}
                    className={`btn ${selectedSeverityFilter === sev ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ height: '36px', minHeight: '36px', padding: '0 12px' }}
                    onClick={() => setSelectedSeverityFilter(sev)}
                  >
                    {sev}
                  </button>
                ))}
              </div>

              {/* Category Filter Pills */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', alignItems: 'center' }}>
                <span className="caption" style={{ marginRight: '4px' }}>Category:</span>
                {(['ALL', 'IAM', 'Storage', 'Network', 'Encryption', 'Logging'] as const).map(cat => (
                  <button
                    key={cat}
                    className={`btn ${selectedCategoryFilter === cat ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ height: '32px', minHeight: '32px', padding: '0 10px', fontSize: '11px' }}
                    onClick={() => setSelectedCategoryFilter(cat)}
                  >
                    {cat}
                  </button>
                ))}
              </div>

              {/* Search input with 44px min height */}
              <div style={{ flexGrow: 1, minWidth: '220px', maxWidth: '320px' }}>
                <input
                  type="text"
                  className="form-input"
                  placeholder="Filter by title, ID, or ARN..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>
            </div>

            {/* Master-Detail Layout */}
            {findings.length === 0 ? (
              <div className="state-empty">
                <div className="state-empty-title">No Telemetry or Security Findings Ingested</div>
                <p>Upload a cloud telemetry dataset (.json or .csv) or load a benchmark to trigger the ML risk engine and compliance monitors.</p>
                <button
                  className="btn btn-primary"
                  style={{ marginTop: '16px' }}
                  onClick={() => setActiveTab('ingestion')}
                >
                  <UploadCloud size={15} />
                  <span>Go to Ingestion Engine</span>
                </button>
              </div>
            ) : filteredFindings.length === 0 ? (
              /* REQUIRED STATE: EMPTY */
              <div className="state-empty">
                <div className="state-empty-title">No Security Findings Match Filters</div>
                <p>Try resetting the cloud provider, severity filter, category, or search term.</p>
                <button
                  className="btn btn-secondary"
                  style={{ marginTop: '16px' }}
                  onClick={() => {
                    setSelectedCloudFilter('ALL');
                    setSelectedSeverityFilter('ALL');
                    setSelectedCategoryFilter('ALL');
                    setSearchQuery('');
                  }}
                >
                  Reset All Filters
                </button>
              </div>
            ) : (
              <div className="grid-master-detail">
                {/* Findings List (Master) */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '720px', overflowY: 'auto' }}>
                  {filteredFindings.map(f => {
                    const isSelected = selectedFinding?.id === f.id;
                    const st = findingStatuses[f.id] || 'OPEN';
                    return (
                      <div
                        key={f.id}
                        tabIndex={0}
                        role="button"
                        className={`surface-card surface-card-interactive ${isSelected ? 'is-selected' : ''}`}
                        onClick={() => setSelectedFinding(f)}
                        onKeyDown={(e) => { if (e.key === 'Enter') setSelectedFinding(f); }}
                        style={{ padding: '16px' }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                            <span className={`tag ${f.severity === 'CRITICAL' ? 'tag-critical' : f.severity === 'HIGH' ? 'tag-warning' : ''}`}>
                              {f.severity}
                            </span>
                            <span className={`tag ${st === 'RESOLVED' ? 'status-pill-resolved' : st === 'IN_PROGRESS' ? 'status-pill-progress' : 'status-pill-open'}`} style={{ fontSize: '10px' }}>
                              {st.replace('_', ' ')}
                            </span>
                          </div>
                          <span className="caption code-text">{f.cloud}</span>
                        </div>
                        <div style={{ fontWeight: 700, fontSize: '14px', marginBottom: '6px', color: 'var(--text-primary)' }}>
                          {f.title}
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span className="caption code-text">{f.id}</span>
                          <span className="caption">Score: <b>{f.riskScore}</b></span>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Finding Details (Detail) */}
                {selectedFinding && (
                  <div className="surface-card" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px', marginBottom: '8px' }}>
                        <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                          <span className={`tag ${selectedFinding.severity === 'CRITICAL' ? 'tag-critical' : 'tag-warning'}`}>
                            {selectedFinding.severity}
                          </span>
                          <span className="tag">{selectedFinding.cloud}</span>
                          <span className="tag tag-accent">{selectedFinding.category}</span>
                          <span className="caption code-text">{selectedFinding.id}</span>
                        </div>

                        {/* Triage Lifecycle State Buttons */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span className="caption" style={{ fontSize: '11px' }}>Triage:</span>
                          {(['OPEN', 'IN_PROGRESS', 'RESOLVED'] as const).map(st => (
                            <button
                              key={st}
                              className={`btn ${findingStatuses[selectedFinding.id] === st ? 'btn-primary' : 'btn-secondary'}`}
                              style={{ height: '26px', minHeight: '26px', padding: '0 8px', fontSize: '11px' }}
                              onClick={() => handleFindingStatusUpdate(selectedFinding.id, st)}
                            >
                              {st.replace('_', ' ')}
                            </button>
                          ))}
                        </div>
                      </div>

                      <h2>{selectedFinding.title}</h2>
                      <div style={{ marginTop: '8px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '8px' }}>
                        <div>
                          <span className="caption">Target Resource ARN:</span>
                          <div className="code-text" style={{ marginTop: '2px', wordBreak: 'break-all' }}>
                            {selectedFinding.resourceId}
                          </div>
                        </div>
                        <button
                          className="btn btn-primary"
                          style={{ height: '32px', minHeight: '32px', padding: '0 12px', fontSize: '12px' }}
                          onClick={() => handleExecutePlaybook(`Remediate finding ${selectedFinding.id}: ${selectedFinding.title}`)}
                        >
                          <Terminal size={14} />
                          <span>Dispatch to SecOps Console</span>
                        </button>
                      </div>
                    </div>

                    {/* Attack Vector */}
                    {selectedFinding.attackVector && (
                      <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-primary)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span className="caption" style={{ fontWeight: 700, textTransform: 'uppercase' }}>Threat Attack Vector</span>
                          <span className="tag tag-accent">MITRE ATT&CK</span>
                        </div>
                        <p style={{ marginTop: '4px', fontSize: '14px' }}>{selectedFinding.attackVector}</p>
                      </div>
                    )}

                    {/* Grounded Security Explanation (LLM / Evidence-Grounded Engine) */}
                    <div
                      id="grounded-security-explanation"
                      data-testid="grounded-security-explanation"
                      className="surface-card"
                      style={{
                        border: '1px solid rgba(56, 189, 248, 0.35)',
                        backgroundColor: 'rgba(15, 23, 42, 0.75)',
                        position: 'relative',
                        padding: '16px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '12px'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <div style={{ width: '28px', height: '28px', borderRadius: '6px', backgroundColor: 'rgba(56, 189, 248, 0.15)', border: '1px solid rgba(56, 189, 248, 0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                            <Sparkles size={14} style={{ color: '#38bdf8' }} />
                          </div>
                          <div>
                            <div style={{ fontWeight: 700, fontSize: '14px', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                              <span>Grounded Security Explanation</span>
                              <span className="tag" style={{ backgroundColor: 'rgba(16, 185, 129, 0.15)', color: '#34d399', border: '1px solid rgba(52, 211, 153, 0.3)', fontSize: '10px' }}>
                                <CheckCircle2 size={10} style={{ marginRight: '4px' }} />
                                100% Grounded in Evidence
                              </span>
                            </div>
                            <span className="caption" style={{ fontSize: '11px' }}>
                              Strict anti-hallucination boundary • Synthesized from verified pipeline facts
                            </span>
                          </div>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span className="tag" style={{ fontSize: '10px', fontFamily: 'monospace' }}>
                            {selectedFindingExplanation?.model_used || 'deterministic-grounded-engine'}
                          </span>
                          <button
                            className="btn btn-secondary"
                            style={{ height: '28px', minHeight: '28px', padding: '0 8px', fontSize: '11px' }}
                            disabled={isLoadingExplanation}
                            onClick={() => fetchExplanationForFinding(selectedFinding)}
                            title="Re-synthesize verified security explanation"
                          >
                            <RefreshCw size={12} className={isLoadingExplanation ? 'animate-spin' : ''} />
                            <span>{isLoadingExplanation ? 'Synthesizing...' : 'Refresh'}</span>
                          </button>
                        </div>
                      </div>

                      {isLoadingExplanation ? (
                        <div style={{ padding: '24px', textAlign: 'center' }}>
                          <RefreshCw size={20} className="animate-spin" style={{ color: '#38bdf8', margin: '0 auto 8px auto' }} />
                          <div className="caption">Compiling verified telemetry, SHAP attributions, and compliance impact...</div>
                        </div>
                      ) : explanationError ? (
                        <div style={{ padding: '16px', border: '1px solid rgba(245, 158, 11, 0.3)', borderRadius: '4px', backgroundColor: 'rgba(245, 158, 11, 0.05)', color: 'var(--text-secondary)', fontSize: '13px' }}>
                          <div style={{ fontWeight: 600, color: 'var(--status-warning)', marginBottom: '4px' }}>Explanation Unavailable</div>
                          <div>{explanationError}</div>
                        </div>
                      ) : selectedFindingExplanation ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                          {/* Risk Banner */}
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 12px', borderRadius: '4px', backgroundColor: 'rgba(0, 0, 0, 0.4)', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span className="caption" style={{ fontWeight: 700 }}>VERIFIED RISK SEVERITY:</span>
                              <span className={`tag ${selectedFindingExplanation.risk === 'CRITICAL' ? 'tag-critical' : selectedFindingExplanation.risk === 'HIGH' ? 'tag-warning' : ''}`} style={{ fontSize: '11px' }}>
                                {selectedFindingExplanation.risk}
                              </span>
                            </div>
                            <span className="caption code-text" style={{ fontSize: '11px' }}>
                              Grounding Score: <b>{(selectedFindingExplanation.grounding_score * 100).toFixed(0)}%</b>
                            </span>
                          </div>

                          {/* What Happened */}
                          <div>
                            <div className="caption" style={{ fontWeight: 700, color: '#38bdf8', textTransform: 'uppercase', marginBottom: '3px' }}>
                              What Happened
                            </div>
                            <p style={{ fontSize: '13px', lineHeight: 1.5, margin: 0, color: 'var(--text-primary)' }}>
                              {selectedFindingExplanation.what_happened}
                            </p>
                          </div>

                          {/* Why It Matters */}
                          <div>
                            <div className="caption" style={{ fontWeight: 700, color: '#fbbf24', textTransform: 'uppercase', marginBottom: '3px' }}>
                              Why It Matters
                            </div>
                            <p style={{ fontSize: '13px', lineHeight: 1.5, margin: 0, color: 'var(--text-secondary)' }}>
                              {selectedFindingExplanation.why_it_matters}
                            </p>
                          </div>

                          {/* Verified Evidence Breakdown */}
                          {selectedFindingExplanation.evidence && selectedFindingExplanation.evidence.length > 0 && (
                            <div>
                              <div className="caption" style={{ fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
                                Verified Pipeline Evidence
                              </div>
                              <ul style={{ margin: 0, paddingLeft: '18px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                {selectedFindingExplanation.evidence.map((item, idx) => (
                                  <li key={idx} style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                                    {item}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {/* Statutory Compliance Impact */}
                          <div>
                            <div className="caption" style={{ fontWeight: 700, color: 'var(--status-critical)', textTransform: 'uppercase', marginBottom: '3px' }}>
                              Compliance Impact
                            </div>
                            <p style={{ fontSize: '13px', lineHeight: 1.5, margin: 0, color: 'var(--text-secondary)' }}>
                              {selectedFindingExplanation.compliance_impact}
                            </p>
                          </div>

                          {/* Recommended Action */}
                          <div style={{ padding: '10px 12px', borderRadius: '4px', backgroundColor: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.25)' }}>
                            <div className="caption" style={{ fontWeight: 700, color: '#34d399', textTransform: 'uppercase', marginBottom: '3px' }}>
                              Recommended Non-Destructive Remediation
                            </div>
                            <p style={{ fontSize: '13px', lineHeight: 1.5, margin: 0, color: 'var(--text-primary)' }}>
                              {selectedFindingExplanation.recommended_action}
                            </p>
                          </div>
                        </div>
                      ) : null}
                    </div>

                    {/* TreeSHAP Feature Attribution */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span className="caption">TreeSHAP Risk Escalator:</span>
                        <span className="code-text"><b>+{Math.round(selectedFinding.shapImpact * 100)}%</b> risk weight</span>
                      </div>
                      <div style={{ width: '100%', height: '6px', backgroundColor: 'var(--bg-primary)', borderRadius: '2px', overflow: 'hidden' }}>
                        <div
                          style={{
                            width: `${Math.round(selectedFinding.shapImpact * 100 * 2)}%`,
                            height: '100%',
                            backgroundColor: 'var(--accent)',
                            borderRadius: '2px'
                          }}
                        />
                      </div>
                      <span className="caption code-text">{selectedFinding.shapTopFeature}</span>
                      <button
                        className="btn btn-secondary"
                        onClick={() => {
                          setActiveTab('ml-engine');
                          explainEventWithShap();
                        }}
                        style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '6px', alignSelf: 'flex-start', fontSize: '12px', padding: '5px 10px' }}
                      >
                        <Activity size={13} />
                        <span>Deconstruct in TreeSHAP Waterfall</span>
                      </button>
                    </div>

                    {/* Compliance Violations */}
                    <div>
                      <span className="caption">Regulatory Benchmark Violations:</span>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '6px' }}>
                        {selectedFinding.complianceViolation.map(c => (
                          <span key={c} className="tag tag-warning">{c}</span>
                        ))}
                      </div>
                    </div>

                    {/* Multi-Platform Remediation Code Panes */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                      {/* Automated CLI Remediation */}
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <span className="caption">Cloud CLI Remediation Script:</span>
                          <button
                            className="btn btn-secondary"
                            style={{ height: '32px', minHeight: '32px', padding: '0 8px', fontSize: '12px' }}
                            onClick={() => copyToClipboard(selectedFinding.cliCommand, 'cli', 'CLI Command copied')}
                          >
                            {copiedKey === 'cli' ? <Check size={14} /> : <Copy size={14} />}
                            <span>{copiedKey === 'cli' ? 'Copied' : 'Copy'}</span>
                          </button>
                        </div>
                        <pre className="code-snippet-box"><code>{selectedFinding.cliCommand}</code></pre>
                      </div>

                      {/* Terraform Patch */}
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <span className="caption">Zero-Trust Terraform IaC Patch:</span>
                          <button
                            className="btn btn-secondary"
                            style={{ height: '32px', minHeight: '32px', padding: '0 8px', fontSize: '12px' }}
                            onClick={() => copyToClipboard(selectedFinding.terraform, 'tf', 'Terraform snippet copied')}
                          >
                            {copiedKey === 'tf' ? <Check size={14} /> : <Copy size={14} />}
                            <span>{copiedKey === 'tf' ? 'Copied' : 'Copy'}</span>
                          </button>
                        </div>
                        <pre className="code-snippet-box"><code>{selectedFinding.terraform}</code></pre>
                      </div>

                      {/* Python SDK Automation */}
                      {selectedFinding.pythonSnippet && (
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                            <span className="caption">Python Cloud SDK Automation:</span>
                            <button
                              className="btn btn-secondary"
                              style={{ height: '32px', minHeight: '32px', padding: '0 8px', fontSize: '12px' }}
                              onClick={() => copyToClipboard(selectedFinding.pythonSnippet!, 'py', 'Python SDK snippet copied')}
                            >
                              {copiedKey === 'py' ? <Check size={14} /> : <Copy size={14} />}
                              <span>{copiedKey === 'py' ? 'Copied' : 'Copy'}</span>
                            </button>
                          </div>
                          <pre className="code-snippet-box"><code>{selectedFinding.pythonSnippet}</code></pre>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* ═══════════════════════════════════
            TAB 3: COMPLIANCE MATRIX
            ═══════════════════════════════════ */}
        {activeTab === 'compliance' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            {/* Header & Framework Scorecards */}
            <div className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
                <div>
                  <h3>Multi-Cloud Compliance Control Matrix</h3>
                  <p style={{ marginTop: '4px' }}>
                    Evaluated configuration checks mapped against CIS Benchmarks, NIST 800-53, ISO 27001, and PCI-DSS 4.0.
                  </p>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <button
                    className="btn btn-secondary"
                    onClick={loadCompliance}
                    disabled={isLoadingCompliance}
                    style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                  >
                    <RefreshCw size={14} className={isLoadingCompliance ? 'spinner' : ''} />
                    <span>{isLoadingCompliance ? 'Evaluating...' : 'Re-evaluate Compliance'}</span>
                  </button>
                  <button
                    className="btn btn-secondary"
                    onClick={handleExportComplianceReport}
                    style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                  >
                    <Download size={14} />
                    <span>Export Compliance Audit Report (JSON)</span>
                  </button>
                </div>
              </div>

              {/* Data Source Label */}
              <div style={{ marginTop: '12px', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <span className={`tag ${complianceSource === 'evaluated' ? 'tag-pass' : 'tag-warning'}`} style={{ fontSize: '10px', fontWeight: 700 }}>
                  {complianceSource === 'evaluated' ? '● BACKEND EVALUATED POLICIES' : '▲ OFFLINE FALLBACK BENCHMARKS'}
                </span>
                {complianceSummary?.overall_pass_rate !== undefined && (
                  <span className="caption" style={{ color: 'var(--text-secondary)' }}>
                    Evaluated <b>{complianceSummary.total_controls}</b> Controls: <b>{complianceSummary.passed_controls}</b> Passing, <b>{complianceSummary.failed_controls}</b> Failing. Overall Pass Rate: <b>{Math.round(complianceSummary.overall_pass_rate)}%</b>
                  </span>
                )}
              </div>

              {/* Dynamic Framework Benchmark Scorecards */}
              <div className="grid-metrics" style={{ marginTop: '16px' }}>
                {frameworkCards.map(fw => (
                  <div key={fw.name} style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-surface-subtle)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: 700, fontSize: '13px' }}>{fw.name}</span>
                      <span className="code-text" style={{ fontWeight: 700, color: fw.pct === 100 ? 'var(--status-pass)' : fw.pct >= 50 ? 'var(--status-warning)' : 'var(--status-critical)' }}>
                        {fw.score}
                      </span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '6px' }}>
                      <span className="caption">Passing Controls:</span>
                      <span className="code-text">{fw.pass} / {fw.total}</span>
                    </div>
                    <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '2px', marginTop: '8px', overflow: 'hidden' }}>
                      <div style={{ width: `${fw.pct}%`, height: '100%', backgroundColor: fw.pct === 100 ? 'var(--status-pass)' : fw.pct >= 50 ? 'var(--status-warning)' : 'var(--status-critical)' }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Filter Toolbar */}
            <div className="surface-card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', padding: '12px 16px' }}>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                <span className="caption">Status Filter:</span>
                {(['ALL', 'PASS', 'FAIL', 'PARTIAL'] as const).map(st => (
                  <button
                    key={st}
                    className={`btn ${complianceStatusFilter === st ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ height: '30px', minHeight: '30px', padding: '0 10px', fontSize: '12px' }}
                    onClick={() => setComplianceStatusFilter(st)}
                  >
                    {st}
                  </button>
                ))}
              </div>

              <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                <span className="caption">Framework Filter:</span>
                {(['ALL', 'CIS AWS 1.4', 'CIS Azure 2.0', 'NIST 800-53', 'PCI-DSS 4.0', 'ISO 27001'] as const).map(fw => (
                  <button
                    key={fw}
                    className={`btn ${complianceFrameworkFilter === fw ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ height: '30px', minHeight: '30px', padding: '0 10px', fontSize: '12px' }}
                    onClick={() => setComplianceFrameworkFilter(fw)}
                  >
                    {fw}
                  </button>
                ))}
              </div>
            </div>

            {/* Control Table */}
            {complianceControls.length === 0 ? (
              <div className="state-empty" style={{ margin: '16px 0' }}>
                <div className="state-empty-title">No Evaluated Compliance Data</div>
                <p>No compliance policy evaluations have been executed yet. Ingest telemetry or load a benchmark dataset to evaluate multi-cloud controls.</p>
                <button
                  className="btn btn-primary"
                  style={{ marginTop: '16px' }}
                  onClick={() => setActiveTab('ingestion')}
                >
                  <UploadCloud size={15} />
                  <span>Go to Ingestion Engine</span>
                </button>
              </div>
            ) : (
            <div className="surface-card" style={{ overflowX: 'auto', padding: 0 }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', minWidth: '600px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)', backgroundColor: 'var(--bg-primary)' }}>
                    <th style={{ padding: '12px 16px', fontSize: '13px', color: 'var(--text-secondary)' }}>Control ID</th>
                    <th style={{ padding: '12px 16px', fontSize: '13px', color: 'var(--text-secondary)' }}>Control Specification</th>
                    <th style={{ padding: '12px 16px', fontSize: '13px', color: 'var(--text-secondary)' }}>Framework</th>
                    <th style={{ padding: '12px 16px', fontSize: '13px', color: 'var(--text-secondary)' }}>Status</th>
                    <th style={{ padding: '12px 16px', fontSize: '13px', color: 'var(--text-secondary)' }}>Evaluated</th>
                    <th style={{ padding: '12px 16px', fontSize: '13px', color: 'var(--text-secondary)' }}>Failed</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredComplianceControls.map(c => (
                    <tr key={c.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '14px 16px' }} className="code-text"><b>{c.id}</b></td>
                      <td style={{ padding: '14px 16px', maxWidth: '400px' }}>{c.name}</td>
                      <td style={{ padding: '14px 16px' }}>
                        <span className="tag">{c.framework}</span>
                      </td>
                      <td style={{ padding: '14px 16px' }}>
                        <span className={`tag ${c.status === 'PASS' ? 'tag-pass' : c.status === 'FAIL' ? 'tag-critical' : 'tag-warning'}`}>
                          {c.status}
                        </span>
                      </td>
                      <td style={{ padding: '14px 16px' }}>{c.evaluatedResources}</td>
                      <td style={{ padding: '14px 16px' }}>
                        <span style={{ color: c.failedCount > 0 ? 'var(--status-critical)' : 'var(--text-secondary)', fontWeight: 700 }}>
                          {c.failedCount}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            )}
          </div>
        )}

        {/* ═══════════════════════════════════
            TAB 4: ML & SHAP ENGINE
            ═══════════════════════════════════ */}
        {activeTab === 'ml-engine' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
            {/* Active ML Model Status Card */}
            <div className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <h3>Phase 5: Machine Learning Anomaly Detection</h3>
                    <span className="tag" style={{ backgroundColor: 'var(--accent)', color: 'var(--accent-contrast)', fontWeight: 700 }}>
                      {modelInfo?.status === 'ready' ? 'ONLINE (ACTIVE)' : 'TRAINED (LOCAL)'}
                    </span>
                  </div>
                  <p className="caption" style={{ marginTop: '2px' }}>
                    Unsupervised scikit-learn Isolation Forest calibrated for multi-cloud security telemetry
                  </p>
                </div>
                <button
                  className="btn btn-secondary"
                  onClick={runLiveMlInference}
                  disabled={isInferring || rawEvents.length === 0}
                  style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
                >
                  <Activity size={15} />
                  <span>{isInferring ? 'Scoring Telemetry...' : 'Run Live ML Inference Scan'}</span>
                </button>
              </div>

              <div className="grid-4col" style={{ gap: '16px' }}>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Algorithm</span>
                  <div className="code-text" style={{ fontSize: '14px', fontWeight: 700, marginTop: '4px' }}>
                    {modelInfo?.algorithm || 'IsolationForest'}
                  </div>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Model Version</span>
                  <div className="code-text" style={{ fontSize: '14px', fontWeight: 700, marginTop: '4px' }}>
                    {modelInfo?.model_version || 'isolation-forest-v1'}
                  </div>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Training Dataset</span>
                  <div className="code-text" style={{ fontSize: '14px', fontWeight: 700, marginTop: '4px' }}>
                    {modelInfo?.training_records_count ? `${modelInfo.training_records_count.toLocaleString()} events` : 'Unavailable'}
                  </div>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Engineered Features</span>
                  <div className="code-text" style={{ fontSize: '14px', fontWeight: 700, marginTop: '4px' }}>
                    {modelInfo?.feature_count ? `${modelInfo.feature_count} dimensions` : 'Unavailable'}
                  </div>
                </div>
              </div>

              {/* Live Inference Results Pane */}
              {mlInferenceResult && (
                <div style={{ marginTop: '20px', padding: '16px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-primary)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                    <span className="code-text" style={{ fontWeight: 700 }}>
                      Live Inference Result ({mlInferenceResult.anomalies_detected} Anomalies / {mlInferenceResult.total_events} Scored)
                    </span>
                    <span className="caption">Rate: {Math.round(mlInferenceResult.anomaly_rate * 100)}%</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {mlInferenceResult.predictions.map((p: any, idx: number) => (
                      <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px', border: '1px solid var(--border)', borderRadius: '2px' }}>
                        <span className="code-text" style={{ fontSize: '13px' }}>
                          Event #{idx + 1}: Score = <b>{Math.round(p.anomaly_score * 100)}%</b> (Raw: {p.raw_score})
                        </span>
                        <span
                          className="tag"
                          style={{
                            backgroundColor: p.is_anomaly ? 'var(--status-critical)' : 'transparent',
                            borderColor: p.is_anomaly ? 'var(--status-critical)' : 'var(--border)',
                            color: p.is_anomaly ? '#fff' : 'var(--text-secondary)'
                          }}
                        >
                          {p.is_anomaly ? 'STATISTICAL ANOMALY' : 'NORMAL INLIER'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Phase 6: Supervised Risk Classification Model Card (XGBoost) */}
            <div className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <h3>Phase 6: Supervised Risk Classification Engine</h3>
                    <span className="tag" style={{ backgroundColor: 'var(--accent)', color: 'var(--accent-contrast)', fontWeight: 700 }}>
                      {supervisedModelInfo?.status === 'ready' ? 'ONLINE (ACTIVE)' : 'TRAINED (LOCAL)'}
                    </span>
                  </div>
                  <p className="caption" style={{ marginTop: '2px' }}>
                    Dual-head XGBoost Gradient Boosted Trees for incident severity classification and continuous risk scoring
                  </p>
                </div>
                <button
                  className="btn btn-secondary"
                  onClick={runLiveSupervisedScan}
                  disabled={isSupervisedInferring || rawEvents.length === 0}
                  style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
                >
                  <Activity size={15} />
                  <span>{isSupervisedInferring ? 'Classifying Risk...' : 'Run Live Supervised Risk Scan'}</span>
                </button>
              </div>

              <div className="grid-4col" style={{ gap: '16px' }}>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Algorithm</span>
                  <div className="code-text" style={{ fontSize: '13px', fontWeight: 700, marginTop: '4px' }}>
                    {supervisedModelInfo?.algorithm || 'XGBoost (Classifier + Regressor)'}
                  </div>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Model Version</span>
                  <div className="code-text" style={{ fontSize: '13px', fontWeight: 700, marginTop: '4px' }}>
                    {supervisedModelInfo?.model_version || 'supervised-xgboost-v1'}
                  </div>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Dataset & Split</span>
                  <div className="code-text" style={{ fontSize: '13px', fontWeight: 700, marginTop: '4px' }}>
                    {supervisedModelInfo?.training_records_count ? `${supervisedModelInfo.training_records_count.toLocaleString()} events` : 'Unavailable'}
                  </div>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Evaluation Metrics</span>
                  <div className="code-text" style={{ fontSize: '13px', fontWeight: 700, marginTop: '4px' }}>
                    {supervisedModelInfo?.metrics?.mae ? `MAE: ${supervisedModelInfo.metrics.mae} pts | R²: ${supervisedModelInfo?.metrics?.r2 ?? 'N/A'}` : 'Unavailable'}
                  </div>
                </div>
              </div>

              {/* Live Supervised Classification Results Pane */}
              {supervisedRiskResult && (
                <div style={{ marginTop: '20px', padding: '16px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-primary)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                    <span className="code-text" style={{ fontWeight: 700 }}>
                      Live Supervised Inference ({supervisedRiskResult.total_events} Events Processed — Mean Risk: {supervisedRiskResult.mean_risk_score}/100)
                    </span>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      {Object.entries(supervisedRiskResult.severity_counts || {}).map(([sev, count]: [string, any]) => (
                        <span key={sev} className="tag" style={{ fontSize: '10px' }}>
                          {sev.toUpperCase()}: {count}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {supervisedRiskResult.predictions.map((p: any, idx: number) => {
                      const sevUpper = (p.predicted_severity || 'LOW').toUpperCase();
                      const sevClass = sevUpper === 'CRITICAL' ? 'tag-critical' : sevUpper === 'HIGH' ? 'tag-warning' : sevUpper === 'MEDIUM' ? 'tag' : 'tag-pass';
                      return (
                        <div key={idx} style={{ display: 'flex', flexDirection: 'column', gap: '6px', padding: '10px 12px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-surface)' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span className="code-text" style={{ fontWeight: 700 }}>Telemetry Event #{idx + 1}</span>
                              <span className={`tag ${sevClass}`}>
                                {sevUpper}
                              </span>
                              <span className="caption" style={{ fontSize: '12px' }}>
                                Confidence: <b>{Math.round(p.confidence * 100)}%</b>
                              </span>
                            </div>
                            <span className="code-text" style={{ fontWeight: 700 }}>
                              Predicted Risk: <span style={{ color: p.predicted_risk_score >= 70 ? 'var(--status-critical)' : p.predicted_risk_score >= 40 ? 'var(--status-warning)' : 'var(--status-pass)' }}>{p.predicted_risk_score} / 100</span>
                            </span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '2px' }}>
                            <span className="caption" style={{ fontSize: '11px', minWidth: '75px' }}>Softmax Dist:</span>
                            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                              {Object.entries(p.severity_probabilities || {}).map(([s, prob]: [string, any]) => (
                                <span key={s} className="caption code-text" style={{ fontSize: '11px' }}>
                                  {s}: {Math.round(prob * 100)}%
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* Risk Simulator Sandbox */}
            <div className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div>
                  <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Sliders size={16} style={{ color: 'var(--accent)' }} />
                    <span>TreeSHAP Risk Sandbox Simulator</span>
                  </h3>
                  <p className="caption" style={{ marginTop: '2px' }}>
                    Adjust telemetry weights to simulate dynamic machine learning risk scoring
                  </p>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <span className="caption">Simulated Score:</span>
                  <div className="h2" style={{ color: simulatedScore > 75 ? 'var(--status-critical)' : 'var(--accent)' }}>
                    {simulatedScore} / 100
                  </div>
                </div>
              </div>

              <div className="grid-2col">
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="caption">Privilege Escalation Exposure:</span>
                    <span className="code-text">{simPrivilege}%</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={simPrivilege}
                    onChange={(e) => setSimPrivilege(Number(e.target.value))}
                    style={{ width: '100%', accentColor: 'var(--accent)', height: '24px' }}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="caption">Public Internet Ingress Scope:</span>
                    <span className="code-text">{simExposure}%</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={simExposure}
                    onChange={(e) => setSimExposure(Number(e.target.value))}
                    style={{ width: '100%', accentColor: 'var(--accent)', height: '24px' }}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="caption">Blast Radius (Connected VPCs/Tenants):</span>
                    <span className="code-text">{simRadius}%</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={simRadius}
                    onChange={(e) => setSimRadius(Number(e.target.value))}
                    style={{ width: '100%', accentColor: 'var(--accent)', height: '24px' }}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="caption">Cryptographic Weakness (Missing CMEK):</span>
                    <span className="code-text">{simEncryption}%</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={simEncryption}
                    onChange={(e) => setSimEncryption(Number(e.target.value))}
                    style={{ width: '100%', accentColor: 'var(--accent)', height: '24px' }}
                  />
                </div>
              </div>
            </div>

            {/* Phase 7: TreeSHAP Global Feature Attributions */}
            <div className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <h3>Top TreeSHAP Global Feature Attributions</h3>
                    <span className="tag" style={{ backgroundColor: 'var(--accent)', color: 'var(--accent-contrast)', fontWeight: 700 }}>
                      PHASE 7 (EXPLAINABILITY)
                    </span>
                  </div>
                  <p className="caption" style={{ marginTop: '2px' }}>
                    Mean absolute Shapley values (TreeSHAP) quantifying global feature impact across multi-cloud infrastructure
                  </p>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <span className="caption">Baseline Risk:</span>
                  <div className="code-text" style={{ fontSize: '15px', fontWeight: 700 }}>
                    {globalShapAttributions?.base_value !== undefined ? `${globalShapAttributions.base_value} pts` : 'Unavailable'}
                  </div>
                </div>
              </div>

              {/* Domain Distribution Chips */}
              {globalShapAttributions?.domain_distribution && (
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '16px', padding: '10px', backgroundColor: 'var(--bg-primary)', borderRadius: '4px', border: '1px solid var(--border)' }}>
                  <span className="caption" style={{ alignSelf: 'center', marginRight: '4px' }}>Domain Impact:</span>
                  {Object.entries(globalShapAttributions.domain_distribution).map(([dom, pct]) => (
                    <span key={dom} className="tag" style={{ fontSize: '11px' }}>
                      {dom}: <b>{pct}%</b>
                    </span>
                  ))}
                </div>
              )}

              {globalShapAttributions?.top_global_features && globalShapAttributions.top_global_features.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  {globalShapAttributions.top_global_features.map(item => (
                  <div key={item.feature_name} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className="code-text" style={{ fontWeight: 600 }}>{item.display_name}</span>
                        <span className="caption" style={{ fontSize: '11px' }}>({item.feature_name})</span>
                      </div>
                      <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <span className="tag">{item.domain}</span>
                        <span className="code-text"><b>+{item.relative_percentage}%</b></span>
                      </div>
                    </div>
                    <div style={{ width: '100%', height: '6px', backgroundColor: 'var(--bg-primary)', borderRadius: '2px', overflow: 'hidden' }}>
                      <div
                        style={{
                          width: `${Math.min(item.relative_percentage * 2.5, 100)}%`,
                          height: '100%',
                          backgroundColor: 'var(--accent)',
                          borderRadius: '2px'
                        }}
                      />
                    </div>
                    {item.description && (
                      <span className="caption" style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                        {item.description}
                      </span>
                    )}
                  </div>
                ))}
              </div>
              ) : (
                <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                  Global TreeSHAP feature attributions unavailable. Ingest telemetry to compute attributions across cloud resources.
                </div>
              )}
            </div>

            {/* TreeSHAP Local Instance Attribution Explainer */}
            <div className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <h3>TreeSHAP Local Incident Attribution Waterfall</h3>
                    <span className="tag tag-warning">ADDITIVE SHAP</span>
                  </div>
                  <p className="caption" style={{ marginTop: '2px' }}>
                    Exact Shapley decomposition isolating positive risk enhancers and negative mitigators for individual telemetry incidents
                  </p>
                </div>
                <button
                  className="btn btn-secondary"
                  onClick={() => explainEventWithShap()}
                  disabled={isExplainingEvent || rawEvents.length === 0}
                  style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
                >
                  <Activity size={15} />
                  <span>{isExplainingEvent ? 'Calculating SHAP...' : 'Deconstruct Sample Incident with TreeSHAP'}</span>
                </button>
              </div>

              {selectedEventExplanation ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '16px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-primary)' }}>
                  {/* Additivity Equation Bar */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', paddingBottom: '12px', borderBottom: '1px solid var(--border)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span className="code-text" style={{ fontWeight: 700 }}>
                        Incident: {selectedEventExplanation.event_id || 'N/A'}
                      </span>
                      <span className="caption">
                        Base Risk: <b>{selectedEventExplanation.base_value} pts</b>
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="caption">Explained Score:</span>
                      <span className="code-text" style={{ fontSize: '16px', fontWeight: 700, color: selectedEventExplanation.predicted_risk_score >= 70 ? 'var(--status-critical)' : 'var(--status-warning)' }}>
                        {selectedEventExplanation.predicted_risk_score} / 100
                      </span>
                      <span className={`tag ${selectedEventExplanation.predicted_risk_score >= 70 ? 'tag-critical' : 'tag-warning'}`}>
                        {selectedEventExplanation.predicted_risk_score >= 70 ? 'CRITICAL RISK' : 'ELEVATED RISK'}
                      </span>
                    </div>
                  </div>

                  {/* 2-Column: Drivers vs Mitigators */}
                  <div className="grid-2col" style={{ gap: '16px' }}>
                    {/* Top Drivers */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <span className="caption" style={{ fontWeight: 700, color: 'var(--status-critical)', textTransform: 'uppercase' }}>
                        ▲ Top Risk Drivers (+pts added)
                      </span>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {selectedEventExplanation.top_risk_drivers.map((d, i) => (
                          <div key={i} style={{ padding: '8px 10px', border: '1px solid var(--border)', borderRadius: '3px', backgroundColor: 'var(--bg-surface)' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <span className="code-text" style={{ fontWeight: 600, fontSize: '12px' }}>{d.display_name}</span>
                                <span className="tag" style={{ fontSize: '10px' }}>{d.domain}</span>
                              </div>
                              <span className="code-text" style={{ color: 'var(--status-critical)', fontWeight: 700, fontSize: '12px' }}>
                                +{d.shap_value} pts
                              </span>
                            </div>
                            <p className="caption" style={{ marginTop: '3px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                              {d.description}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Top Mitigators */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <span className="caption" style={{ fontWeight: 700, color: 'var(--status-pass)', textTransform: 'uppercase' }}>
                        ▼ Protective Factors (-pts mitigated)
                      </span>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {selectedEventExplanation.top_risk_mitigators.length > 0 ? (
                          selectedEventExplanation.top_risk_mitigators.map((m, i) => (
                            <div key={i} style={{ padding: '8px 10px', border: '1px solid var(--border)', borderRadius: '3px', backgroundColor: 'var(--bg-surface)' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                  <span className="code-text" style={{ fontWeight: 600, fontSize: '12px' }}>{m.display_name}</span>
                                  <span className="tag" style={{ fontSize: '10px' }}>{m.domain}</span>
                                </div>
                                <span className="code-text" style={{ color: 'var(--status-pass)', fontWeight: 700, fontSize: '12px' }}>
                                  {m.shap_value} pts
                                </span>
                              </div>
                              <p className="caption" style={{ marginTop: '3px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                                {m.description}
                              </p>
                            </div>
                          ))
                        ) : (
                          <div style={{ padding: '12px', border: '1px dashed var(--border)', borderRadius: '3px', textAlign: 'center' }}>
                            <span className="caption">No mitigating security controls detected for this event.</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div style={{ textAlign: 'center', padding: '24px 16px', border: '1px dashed var(--border)', borderRadius: '4px' }}>
                  <p className="caption">Click &quot;Deconstruct Sample Incident with TreeSHAP&quot; to compute live additive Shapley feature values for a security event.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ═══════════════════════════════════
            TAB 5: DATA INGESTION (ALL 8 STATES)
            ═══════════════════════════════════ */}
        {activeTab === 'ingestion' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <div className="surface-card">
              <h3>Multi-Cloud Data Ingestion Engine</h3>
              <p style={{ marginTop: '4px' }}>
                Upload configuration exports from AWS Config, Azure Resource Graph, or GCP Asset Inventory in JSON or CSV format.
              </p>
            </div>

            {/* Hidden native file input */}
            <input
              type="file"
              ref={fileInputRef}
              accept=".csv,.json,text/csv,application/json"
              style={{ display: 'none' }}
              onChange={handleFileInputChange}
            />

            {/* Dropzone Container */}
            <div className="surface-card" style={{ display: 'flex', flexDirection: 'column', gap: '20px', alignItems: 'center', textAlign: 'center', padding: '40px 24px' }}>
              <UploadCloud size={40} style={{ color: 'var(--accent)' }} />

              <div>
                <div className="h3">Select Configuration Audit File</div>
                <p className="caption" style={{ marginTop: '4px' }}>
                  Supported formats: .json, .csv (Max 50MB)
                </p>
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', justifyContent: 'center' }}>
                <button
                  className="btn btn-secondary"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={uploadStatus === 'loading'}
                  style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                >
                  <FolderUp size={15} />
                  <span>Select CSV / JSON File</span>
                </button>

                <button
                  className={`btn btn-primary ${uploadStatus === 'loading' ? 'is-loading' : ''}`}
                  onClick={handleUploadButtonClick}
                  disabled={uploadStatus === 'loading'}
                >
                  {uploadStatus === 'loading' && <span className="spinner" style={{ marginRight: '6px' }} />}
                  <span>{uploadStatus === 'loading' ? 'Processing Telemetry...' : 'Upload & Analyze File'}</span>
                </button>



                {uploadStatus !== 'idle' && (
                  <button
                    className="btn btn-ghost"
                    onClick={() => {
                      setUploadStatus('idle');
                      setUploadedFileName(null);
                      setLastIngestionResult(null);
                    }}
                  >
                    Reset Ingestion
                  </button>
                )}
              </div>

              {/* Bundled Benchmark Quick Loaders */}
              <div style={{ marginTop: '8px', borderTop: '1px solid var(--border)', paddingTop: '16px', width: '100%', maxWidth: '720px' }}>
                <span className="caption" style={{ display: 'block', marginBottom: '10px', color: 'var(--text-secondary)' }}>
                  Or quickly load bundled multi-cloud benchmark telemetry datasets:
                </span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', justifyContent: 'center' }}>
                  <button
                    className="btn btn-secondary"
                    style={{ height: '32px', minHeight: '32px', padding: '0 10px', fontSize: '12px' }}
                    onClick={() => handleLoadSampleBenchmark('cloudtrail')}
                    disabled={uploadStatus === 'loading'}
                  >
                    Demo / Benchmark: AWS CloudTrail (JSON)
                  </button>
                  <button
                    className="btn btn-secondary"
                    style={{ height: '32px', minHeight: '32px', padding: '0 10px', fontSize: '12px' }}
                    onClick={() => handleLoadSampleBenchmark('azure')}
                    disabled={uploadStatus === 'loading'}
                  >
                    Demo / Benchmark: Azure Activity (JSON)
                  </button>
                  <button
                    className="btn btn-secondary"
                    style={{ height: '32px', minHeight: '32px', padding: '0 10px', fontSize: '12px' }}
                    onClick={() => handleLoadSampleBenchmark('gcp')}
                    disabled={uploadStatus === 'loading'}
                  >
                    Demo / Benchmark: GCP Audit (JSON)
                  </button>
                  <button
                    className="btn btn-secondary"
                    style={{ height: '32px', minHeight: '32px', padding: '0 10px', fontSize: '12px' }}
                    onClick={() => handleLoadSampleBenchmark('attack_scenario')}
                    disabled={uploadStatus === 'loading'}
                  >
                    Demo / Benchmark: Multi-Stage Attack (JSON)
                  </button>
                  <button
                    className="btn btn-secondary"
                    style={{ height: '32px', minHeight: '32px', padding: '0 10px', fontSize: '12px' }}
                    onClick={() => handleLoadSampleBenchmark('synthetic')}
                    disabled={uploadStatus === 'loading'}
                  >
                    Demo / Benchmark: Security Events (CSV)
                  </button>
                </div>
              </div>

              {/* REQUIRED STATE: LOADING */}
              {uploadStatus === 'loading' && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '8px' }}>
                  <span className="spinner" />
                  <span className="caption">Parsing cloud telemetry graph, normalizing schemas, and computing TreeSHAP matrices...</span>
                </div>
              )}

              {/* REQUIRED STATE: COMPLETE */}
              {uploadStatus === 'complete' && (
                <div style={{ padding: '20px', border: '1px solid var(--status-pass-border)', borderRadius: '6px', backgroundColor: 'var(--status-pass-bg)', width: '100%', maxWidth: '720px', textAlign: 'left' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ fontWeight: 700, color: 'var(--status-pass)', fontSize: '16px' }}>Ingestion Successful</div>
                    <span className="tag tag-pass">HTTP 200 OK</span>
                  </div>
                  <div className="caption" style={{ marginTop: '4px', fontSize: '13px' }}>
                    Parsed <b>{uploadedFileName}</b>
                    {lastIngestionResult ? (
                      ` — Processed ${lastIngestionResult.successful_events} events in ${lastIngestionResult.duration_ms}ms with ${lastIngestionResult.risk_summary.anomalies_detected} anomalies and ${lastIngestionResult.risk_summary.findings_count} findings.`
                    ) : (
                      ` — Ingestion pipeline normalized events and synchronized compliance state.`
                    )}
                  </div>

                  {lastIngestionResult && (
                    <div style={{ marginTop: '16px', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '8px' }}>
                      <div style={{ padding: '8px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-surface)' }}>
                        <span className="caption">Total Parsed</span>
                        <div className="code-text" style={{ fontWeight: 700 }}>{lastIngestionResult.total_parsed}</div>
                      </div>
                      <div style={{ padding: '8px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-surface)' }}>
                        <span className="caption">Successful</span>
                        <div className="code-text" style={{ fontWeight: 700, color: 'var(--status-pass)' }}>{lastIngestionResult.successful_events}</div>
                      </div>
                      <div style={{ padding: '8px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-surface)' }}>
                        <span className="caption">Anomalies</span>
                        <div className="code-text" style={{ fontWeight: 700, color: lastIngestionResult.risk_summary.anomalies_detected > 0 ? 'var(--status-critical)' : 'var(--text-primary)' }}>
                          {lastIngestionResult.risk_summary.anomalies_detected}
                        </div>
                      </div>
                      <div style={{ padding: '8px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-surface)' }}>
                        <span className="caption">Findings</span>
                        <div className="code-text" style={{ fontWeight: 700, color: 'var(--status-critical)' }}>{lastIngestionResult.risk_summary.findings_count}</div>
                      </div>
                      <div style={{ padding: '8px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-surface)' }}>
                        <span className="caption">Mean Risk</span>
                        <div className="code-text" style={{ fontWeight: 700 }}>{lastIngestionResult.risk_summary.average_risk_score.toFixed(1)}/100</div>
                      </div>
                    </div>
                  )}

                  <div style={{ marginTop: '16px', display: 'flex', gap: '10px', alignItems: 'center' }}>
                    <button
                      className="btn btn-primary"
                      style={{ height: '32px', minHeight: '32px', padding: '0 12px', fontSize: '12px' }}
                      onClick={() => setActiveTab('findings')}
                    >
                      <span>View Ingested Findings ({findings.length})</span>
                    </button>
                    <button
                      className="btn btn-secondary"
                      style={{ height: '32px', minHeight: '32px', padding: '0 12px', fontSize: '12px' }}
                      onClick={() => setActiveTab('compliance')}
                    >
                      <span>View Evaluated Compliance</span>
                    </button>
                  </div>
                </div>
              )}

              {/* REQUIRED STATE: ERROR */}
              {uploadStatus === 'error' && (
                <div className="state-error" style={{ width: '100%', maxWidth: '720px', textAlign: 'left' }}>
                  <AlertTriangle size={22} style={{ color: 'var(--status-critical)', flexShrink: 0 }} />
                  <div>
                    <div style={{ fontWeight: 700, color: 'var(--status-critical)' }}>Ingestion Error</div>
                    <div className="caption" style={{ marginTop: '2px' }}>
                      {uploadErrorMessage || 'Invalid schema: Missing cloud_provider ARN attributes in rows 12-18. Please upload a standard AWS/Azure/GCP inventory export.'}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Realtime Ingestion Pipeline Telemetry Statistics */}
            <div className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '8px' }}>
                <div>
                  <h3>Ingestion Pipeline Telemetry Statistics</h3>
                  <span className="caption">Verified event telemetry parsed and normalized across cloud providers</span>
                </div>
                <button
                  className="btn btn-secondary"
                  style={{ height: '28px', minHeight: '28px', padding: '0 8px', fontSize: '11px' }}
                  onClick={loadStats}
                >
                  <RefreshCw size={12} />
                  <span>Refresh Stats</span>
                </button>
              </div>

              <div className="grid-metrics">
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Total Events Ingested</span>
                  <div className="h3" style={{ marginTop: '4px' }}>
                    {ingestionStats?.total_events_ingested || rawEvents.length}
                  </div>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Normalized Valid Events</span>
                  <div className="h3" style={{ marginTop: '4px', color: 'var(--status-pass)' }}>
                    {ingestionStats?.valid_events_count || rawEvents.length}
                  </div>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Anomalies Detected</span>
                  <div className="h3" style={{ marginTop: '4px', color: (ingestionStats?.anomalies_detected || 0) > 0 ? 'var(--status-critical)' : 'var(--text-primary)' }}>
                    {ingestionStats?.anomalies_detected ?? 0}
                  </div>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Critical Findings</span>
                  <div className="h3" style={{ marginTop: '4px', color: 'var(--status-critical)' }}>
                    {ingestionStats?.critical_findings_count ?? findings.filter(f => f.severity === 'CRITICAL').length}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ═══════════════════════════════════
            TAB 6: ARCHITECTURE BLUEPRINT
            ═══════════════════════════════════ */}
        {activeTab === 'architecture' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <div className="surface-card">
              <h3>CloudShield IQ System Architecture</h3>
              <p style={{ marginTop: '4px' }}>
                End-to-end telemetry pipeline from multi-cloud discovery to TreeSHAP scoring and automated zero-trust IaC patching.
              </p>
            </div>

            <div className="grid-metrics">
              <div className="surface-card">
                <span className="tag">Stage 1</span>
                <div className="h3" style={{ marginTop: '12px' }}>Telemetry Ingestion</div>
                <p className="caption" style={{ marginTop: '8px' }}>
                  Asynchronous ingestion of IAM policies, security group ingress rules, and KMS encryption state via FastAPI endpoints.
                </p>
              </div>

              <div className="surface-card">
                <span className="tag">Stage 2</span>
                <div className="h3" style={{ marginTop: '12px' }}>Risk Engine</div>
                <p className="caption" style={{ marginTop: '8px' }}>
                  Tree-based machine learning model attributing quantitative risk vectors to cloud configuration parameters.
                </p>
              </div>

              <div className="surface-card">
                <span className="tag">Stage 3</span>
                <div className="h3" style={{ marginTop: '12px' }}>TreeSHAP Explainer</div>
                <p className="caption" style={{ marginTop: '8px' }}>
                  Attribution weights indicating exactly which misconfigurations escalate the composite vulnerability index.
                </p>
              </div>

              <div className="surface-card">
                <span className="tag">Stage 4</span>
                <div className="h3" style={{ marginTop: '12px' }}>IaC Remediation</div>
                <p className="caption" style={{ marginTop: '8px' }}>
                  Synthesized CLI scripts and strict Terraform modules enabling one-click patch deployment to multi-cloud perimeters.
                </p>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* ═══════════════════════════════════
          SECOPS REMEDIATION CONSOLE (FLAT TERMINAL DESIGN)
          ═══════════════════════════════════ */}
      {isConsoleOpen && (
        <aside className="secops-console-panel">
          {/* Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 16px', borderBottom: '1px solid var(--border)', backgroundColor: 'var(--bg-surface-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Terminal size={16} style={{ color: 'var(--accent)' }} />
              <div style={{ fontWeight: 700, fontSize: '13px' }}>Automated Remediation & SecOps Console</div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <button
                className="btn-ghost"
                style={{ fontSize: '11px', padding: '4px 8px', color: 'var(--text-secondary)' }}
                onClick={() => {
                  setConsoleMessages([{
                    id: 'init',
                    sender: 'system',
                    text: 'SecOps Remediation Engine initialized. Buffer cleared. Continuous posture assessment, TreeSHAP quantitative risk attribution, and zero-trust Infrastructure-as-Code mitigation ready.',
                    timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                  }]);
                  showToast('SecOps terminal buffer cleared', 'info');
                }}
                title="Clear buffer"
              >
                Clear
              </button>
              <button
                className="btn-ghost"
                style={{ width: '32px', height: '32px', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 0 }}
                onClick={() => setIsConsoleOpen(false)}
                aria-label="Close Console"
              >
                <X size={16} />
              </button>
            </div>
          </div>

          {/* Messages */}
          <div style={{ flexGrow: 1, padding: '16px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {consoleMessages.map(msg => (
              <div
                key={msg.id}
                style={{
                  alignSelf: msg.sender === 'operator' ? 'flex-end' : 'flex-start',
                  maxWidth: '88%',
                  padding: '12px',
                  borderRadius: '4px',
                  backgroundColor: msg.sender === 'operator' ? 'var(--bg-surface-elevated)' : 'var(--bg-primary)',
                  color: 'var(--text-primary)',
                  border: msg.sender === 'operator' ? '1px solid var(--border-hover)' : '1px solid var(--border)'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
                  <span className="caption code-text" style={{ color: msg.sender === 'operator' ? 'var(--accent)' : 'var(--text-secondary)' }}>
                    {msg.sender === 'operator' ? '$ operator' : 'system@cloudshield'}
                  </span>
                </div>
                <div style={{ fontSize: '13px', lineHeight: 1.5 }}>{msg.text}</div>
                {msg.code && (
                  <div style={{ marginTop: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <span className="caption code-text" style={{ fontSize: '11px', opacity: 0.8 }}>Remediation Synthesizer:</span>
                      <button
                        className="btn-ghost"
                        style={{ fontSize: '11px', padding: '2px 6px', display: 'flex', alignItems: 'center', gap: '4px' }}
                        onClick={() => copyToClipboard(msg.code!, `msg-${msg.id}`, 'Console code copied')}
                      >
                        {copiedKey === `msg-${msg.id}` ? <Check size={12} /> : <Copy size={12} />}
                        <span>{copiedKey === `msg-${msg.id}` ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <pre className="code-snippet-box" style={{ fontSize: '12px', margin: 0 }}>
                      <code>{msg.code}</code>
                    </pre>
                  </div>
                )}
                <div className="caption" style={{ marginTop: '4px', textAlign: 'right', opacity: 0.6, fontSize: '11px' }}>
                  {msg.timestamp}
                </div>
              </div>
            ))}
            {isConsoleExecuting && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px' }}>
                <span className="spinner" />
                <span className="caption">Querying TreeSHAP models and synthesising remediation script...</span>
              </div>
            )}
          </div>

          {/* Quick Command Suggestions */}
          <div style={{ padding: '8px 16px', borderTop: '1px solid var(--border)', backgroundColor: 'var(--bg-surface)', display: 'flex', gap: '6px', overflowX: 'auto' }}>
            {[
              { label: 'Revoke Root IAM Key', cmd: 'Remediate Root IAM access key' },
              { label: 'Apply S3 Access Block', cmd: 'Apply S3 Public Access Block' },
              { label: 'Enforce CloudTrail Logging', cmd: 'Re-enable CloudTrail Logging' },
              { label: 'Audit Compliance Matrix', cmd: 'Audit Compliance Matrix' }
            ].map(item => (
              <button
                key={item.label}
                className="btn btn-secondary"
                style={{ height: '24px', minHeight: '24px', padding: '0 8px', fontSize: '11px', whiteSpace: 'nowrap' }}
                onClick={() => handleExecutePlaybook(item.cmd)}
              >
                {item.label}
              </button>
            ))}
          </div>

          {/* Input Box */}
          <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)', display: 'flex', gap: '8px', backgroundColor: 'var(--bg-surface-subtle)' }}>
            <input
              type="text"
              className="form-input"
              placeholder="Enter remediation query, CVE, or resource ARN..."
              value={consoleInput}
              onChange={(e) => setConsoleInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleExecutePlaybook(); }}
            />
            <button
              className="btn btn-primary"
              style={{ width: '38px', minWidth: '38px', height: '38px', padding: 0 }}
              onClick={() => handleExecutePlaybook()}
              aria-label="Execute command"
            >
              <Send size={15} />
            </button>
          </div>
        </aside>
      )}

      {/* ═══════════════════════════════════
          FOOTER (ENTERPRISE MINIMALIST)
          ═══════════════════════════════════ */}
      <footer style={{ borderTop: '1px solid var(--border)', backgroundColor: 'var(--bg-surface)', padding: '20px 0' }}>
        <div className="app-container" style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '16px' }}>
          <div className="caption">
            CloudShield IQ &copy; 2026. Multi-Cloud Security Posture Assessment & Automated Remediation Framework.
          </div>
          <div style={{ display: 'flex', gap: '16px' }}>
            <a href="#" className="caption" onClick={(e) => { e.preventDefault(); setActiveTab('compliance'); }}>
              Compliance Standards
            </a>
            <a href="#" className="caption" onClick={(e) => { e.preventDefault(); setActiveTab('ml-engine'); }}>
              TreeSHAP Documentation
            </a>
            <a href="#" className="caption" onClick={(e) => { e.preventDefault(); setActiveTab('architecture'); }}>
              System Blueprint
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
