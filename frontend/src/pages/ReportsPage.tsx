import React, { useCallback, useEffect, useState } from 'react';
import {
  FileText,
  Download,
  Printer,
  RefreshCw,
  AlertCircle,
  Terminal,
} from 'lucide-react';
import { api } from '@/services/api';
import { DEMO_REPORT_MARKDOWN } from '@/demo/fixtures';
import { StatePanel } from '@/components/StatePanel';
import { DemoBadge } from '@/components/DemoBadge';
import { PageHeader } from '@/components/PageHeader';
import { ContextSidebar } from '@/components/ContextSidebar';
import { KeyValue } from '@/components/KeyValue';
import { ActiveTab } from '@/components/AppShell';
import { BackendConnectionState } from '@/components/ConnectionStatus';

interface ReportsPageProps {
  isDemoMode: boolean;
  assessmentId: string | null;
  connectionState: BackendConnectionState;
  contextLoading?: boolean;
  contextError?: string | null;
  onRetryContext?: () => void;
  refreshToken?: number;
  onNavigateTab?: (tab: ActiveTab) => void;
}

export const ReportsPage: React.FC<ReportsPageProps> = ({
  isDemoMode,
  assessmentId,
  connectionState,
  contextLoading = false,
  contextError = null,
  onRetryContext,
  refreshToken = 0,
  onNavigateTab,
}) => {
  const [reportMarkdown, setReportMarkdown] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [loadedAt, setLoadedAt] = useState<Date | null>(null);

  const isOffline =
    connectionState === 'offline' || connectionState === 'api_error';

  const fetchReport = useCallback(async () => {
    setLoading(true);
    setError(null);
    setReportMarkdown('');
    setLoadedAt(null);

    if (isDemoMode) {
      setReportMarkdown(DEMO_REPORT_MARKDOWN);
      setLoadedAt(new Date());
      setLoading(false);
      return;
    }

    if (!assessmentId) {
      setLoading(false);
      return;
    }

    try {
      const markdown = await api.getReportMarkdown(assessmentId);
      setReportMarkdown(markdown);
      setLoadedAt(new Date());
    } catch (err: any) {
      setReportMarkdown('');
      setError(
        err?.message || 'Failed to generate the markdown report from the backend.',
      );
    } finally {
      setLoading(false);
    }
  }, [assessmentId, isDemoMode]);

  useEffect(() => {
    fetchReport();
  }, [fetchReport, refreshToken]);

  const downloadName = isDemoMode
    ? `DEMO-${assessmentId || 'ASM'}-report.md`
    : `${assessmentId || 'assessment'}-audit-report.md`;

  const handleDownloadMarkdown = () => {
    if (!reportMarkdown) return;
    const blob = new Blob([reportMarkdown], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = downloadName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const canPrint = !isDemoMode && Boolean(assessmentId) && Boolean(reportMarkdown);

  const handlePrintHtml = () => {
    if (!canPrint || !assessmentId) return;
    window.open(`/api/v1/reports/${assessmentId}/html`, '_blank', 'noopener');
  };

  if (contextLoading && !isDemoMode) {
    return <StatePanel kind="loading" title="Loading workspace context…" />;
  }

  if (contextError && !isDemoMode) {
    return (
      <StatePanel
        kind={isOffline ? 'offline' : 'error'}
        title="Workspace context unavailable"
        description="The engagement and assessment lists could not be loaded, so no report content can be shown."
        errorMessage={contextError}
        onRetry={onRetryContext}
      />
    );
  }

  if (!assessmentId && !isDemoMode) {
    return (
      <StatePanel
        kind="empty"
        title="No assessment available"
        description="A report requires an active assessment from the backend. Create or select an assessment to continue."
      />
    );
  }

  if (loading) {
    return <StatePanel kind="loading" title="Compiling audit report…" />;
  }

  if (error) {
    return (
      <StatePanel
        kind={isOffline ? 'offline' : 'error'}
        title={isOffline ? 'Report backend unreachable' : 'Report request failed'}
        description="No report content is shown because the backend request did not succeed."
        errorMessage={error}
        onRetry={fetchReport}
      />
    );
  }

  return (
    <div className="wb-page-layout">
      <ContextSidebar
        title="Reports & Audit"
        footer={
          <span>
            {isDemoMode
              ? 'Demo fixture report — not live data.'
              : "Reports are generated from the backend's current records for the selected assessment."}
          </span>
        }
      >
        <div className="wb-context-section">
          <div className="wb-section-label">Report context</div>
          <KeyValue
            items={[
              { key: 'Assessment', value: assessmentId || 'No assessment' },
              { key: 'Format', value: 'Markdown + printable HTML' },
              { key: 'Source', value: isDemoMode ? 'DEMO fixture' : 'Backend API' },
              { key: 'Loaded', value: loadedAt ? loadedAt.toLocaleTimeString() : '—' },
            ]}
          />
        </div>

        <div className="wb-context-section">
          <div className="wb-section-label">Format &amp; actions</div>
          <div className="wb-sidebar-actions">
            <button
              type="button"
              onClick={fetchReport}
              className="wb-btn wb-btn-sm"
              title="Regenerate the report from the backend"
            >
              <RefreshCw size={10} /> Refresh report
            </button>
            <button
              type="button"
              onClick={handleDownloadMarkdown}
              className="wb-btn wb-btn-sm"
              disabled={!reportMarkdown}
              title="Download the report content that was actually fetched"
            >
              <Download size={10} /> Download Markdown
            </button>
            <button
              type="button"
              onClick={handlePrintHtml}
              className="wb-btn wb-btn-sm"
              disabled={!canPrint}
              title={
                isDemoMode
                  ? 'Printable HTML is disabled in Demo Mode'
                  : 'Open the backend printable HTML endpoint'
              }
            >
              <Printer size={10} /> Printable HTML
            </button>
          </div>
        </div>

        <div className="wb-context-section">
          <div className="wb-section-label">Audit trail</div>
          <p className="wb-context-note">
            The backend has no separate audit-log endpoint. Execution records are
            available in Check Executions.
          </p>
          {onNavigateTab && (
            <button
              type="button"
              className="wb-btn wb-btn-sm"
              onClick={() => onNavigateTab('executions')}
            >
              <Terminal size={10} /> Open execution audit trail
            </button>
          )}
        </div>
      </ContextSidebar>

      <div className="wb-page-main">
        <PageHeader
          title="Reports & Audit"
          description={
            isDemoMode
              ? 'Preview and download the static demo report fixture.'
              : 'Preview, download, and print reports that are actually returned by the backend.'
          }
          isDemoMode={isDemoMode}
          meta={
            <>
              <span>
                Assessment: <strong>{assessmentId || 'No assessment'}</strong>
              </span>
              <span>
                Status:{' '}
                <strong>
                  {isDemoMode
                    ? 'DEMO fixture loaded'
                    : reportMarkdown
                      ? `Report loaded${loadedAt ? ` at ${loadedAt.toLocaleTimeString()}` : ''}`
                      : 'No report content'}
                </strong>
              </span>
            </>
          }
        />

        <div className="wb-page-body">
          <div className="wb-panel" style={{ height: '100%' }}>
            <div className="wb-panel-header">
              <div className="wb-panel-title">
                <FileText size={14} color="var(--accent)" />
                <span>Defensive security assessment report</span>
                {isDemoMode && <DemoBadge />}
              </div>
              <span className="wb-toolbar-hint">
                {isDemoMode ? 'DEMO REPORT — NOT LIVE' : `GET /reports/${assessmentId}/markdown`}
              </span>
            </div>

            <div className="wb-toolbar">
              <span className="wb-toolbar-label">
                Assessment: <strong>{assessmentId}</strong>
              </span>
              <span className="wb-toolbar-spacer" />
              <div className="wb-toolbar-group" style={{ color: 'var(--status-warn-text)' }}>
                <AlertCircle size={11} />
                <span className="wb-toolbar-hint">
                {isDemoMode
                  ? 'Demo report content comes from static fixtures, not the backend.'
                  : 'Report data is read from the backend for the selected assessment.'}
                </span>
              </div>
            </div>

            <div className="wb-panel-body wb-report-body">
              {reportMarkdown.trim().length === 0 ? (
                <StatePanel
                  kind="empty"
                  title="Report returned no content"
                  description="The backend returned an empty report. No sample report is substituted."
                  onRetry={fetchReport}
                />
              ) : (
                <div className="wb-report-document">
                  <pre>{reportMarkdown}</pre>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
