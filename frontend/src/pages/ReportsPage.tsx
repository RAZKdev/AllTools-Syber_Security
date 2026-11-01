import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  Printer,
  RefreshCw,
  AlertCircle,
} from 'lucide-react';
import { api } from '@/services/api';
import { DEMO_REPORT_MARKDOWN } from '@/demo/fixtures';
import { StatePanel } from '@/components/StatePanel';
import { DemoBadge } from '@/components/DemoBadge';

interface ReportsPageProps {
  isDemoMode: boolean;
}

export const ReportsPage: React.FC<ReportsPageProps> = ({ isDemoMode }) => {
  const [reportMarkdown, setReportMarkdown] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const assessmentId = isDemoMode ? 'DEMO-ASM-001' : 'ASM-001';

  const fetchReport = async () => {
    setLoading(true);
    setError(null);

    if (isDemoMode) {
      setReportMarkdown(DEMO_REPORT_MARKDOWN);
      setLoading(false);
      return;
    }

    try {
      const md = await api.getReportMarkdown(assessmentId);
      setReportMarkdown(md);
    } catch (err: any) {
      setError(err?.message || 'Failed to generate markdown report from backend API');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, [isDemoMode]);

  const handleDownloadMarkdown = () => {
    const blob = new Blob([reportMarkdown], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `audit-report-${assessmentId}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handlePrintHtml = () => {
    if (isDemoMode) {
      window.print();
      return;
    }
    window.open(`/api/v1/reports/${assessmentId}/html`, '_blank');
  };

  if (loading && !isDemoMode) {
    return <StatePanel kind="loading" title="Compiling Audit Report..." />;
  }

  if (error && !isDemoMode) {
    return (
      <StatePanel
        kind="offline"
        title="Report Generator Offline"
        description="Could not compile defensive security report from backend API."
        errorMessage={error}
        onRetry={fetchReport}
      />
    );
  }

  return (
    <div className="wb-panel" style={{ height: '100%' }}>
      {/* Panel Header */}
      <div className="wb-panel-header">
        <div className="wb-panel-title">
          <FileText size={14} color="var(--accent)" />
          <span>Defensive Security Assessment Report & Audit Package</span>
          {isDemoMode && <DemoBadge />}
        </div>

        <div style={{ display: 'flex', gap: '6px' }}>
          <button
            onClick={fetchReport}
            className="wb-btn wb-btn-sm"
            title="Re-generate report with newest findings and executions"
          >
            <RefreshCw size={10} />
            Refresh
          </button>
          <button
            onClick={handleDownloadMarkdown}
            disabled={!reportMarkdown}
            className="wb-btn wb-btn-sm"
            title="Export standalone markdown file"
          >
            <Download size={10} />
            Download Markdown (.md)
          </button>
          <button
            onClick={handlePrintHtml}
            disabled={!reportMarkdown}
            className="wb-btn wb-btn-primary wb-btn-sm"
            title="Open printable HTML version"
          >
            <Printer size={10} />
            Printable HTML
          </button>
        </div>
      </div>

      {/* Toolbar & Meta */}
      <div className="wb-toolbar">
        <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
          Assessment: <strong style={{ color: 'var(--text-primary)' }}>{assessmentId}</strong>
        </span>
        <span style={{ color: 'var(--border-strong)' }}>|</span>
        <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
          Format: <strong style={{ color: 'var(--text-primary)' }}>Audit-Grade Markdown / HTML</strong>
        </span>
        <span style={{ color: 'var(--border-strong)' }}>|</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px', color: 'var(--status-warn-text)' }}>
          <AlertCircle size={11} />
          <span>In-memory session repository: export report before stopping backend.</span>
        </div>
      </div>

      {/* Report Document Preview Pane */}
      <div className="wb-panel-body" style={{ padding: '24px 32px' }}>
        <div
          style={{
            maxWidth: '900px',
            margin: '0 auto',
            background: 'var(--bg-table-zebra)',
            border: '1px solid var(--border-default)',
            borderRadius: '4px',
            padding: '24px 32px',
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.3)',
          }}
        >
          <pre
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              color: 'var(--text-primary)',
              lineHeight: 1.7,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
            }}
          >
            {reportMarkdown}
          </pre>
        </div>
      </div>
    </div>
  );
};
