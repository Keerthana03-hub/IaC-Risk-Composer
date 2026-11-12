/**
 * ThreatReports.jsx (Security Reports - Section 11)
 * ------------------------------------------------
 * Saved security assessment reports with search, severity filter,
 * PDF download, and delete actions.
 */

import React, { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Search,
  FileDown,
  Trash2,
  ExternalLink,
  FileText,
  Clock,
  FolderGit2,
} from 'lucide-react'

import { deleteSavedReport, downloadSavedReportPdf } from '../api'
import { useAnalysis } from '../context/AnalysisContext'
import {
  normalizeSeverity,
  isRealSeverity,
  SEVERITY_ORDER,
  SEVERITY_META,
} from '../utils/risk'
import { formatDateTime } from '../utils/format'
import { friendlyError } from '../utils/errors'

import PageHeader from '../components/common/PageHeader'
import ErrorBanner from '../components/common/ErrorBanner'
import EmptyState from '../components/common/EmptyState'
import SeverityBadge from '../components/common/SeverityBadge'
import ConfirmDialog from '../components/common/ConfirmDialog'
import { CardSkeleton } from '../components/common/Skeleton'

export default function ThreatReports() {
  const navigate = useNavigate()
  const { reports, projects, loading, error, refreshReportList } = useAnalysis()

  const [query, setQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [projectFilter, setProjectFilter] = useState('all')
  const [busyId, setBusyId] = useState(null)
  const [actionError, setActionError] = useState('')
  const [pendingDelete, setPendingDelete] = useState(null)

  const filtered = useMemo(() => {
    return reports.filter(r => {
      if (
        severityFilter !== 'all' &&
        normalizeSeverity(r.overall_risk_level) !== severityFilter
      ) {
        return false
      }
      if (projectFilter !== 'all' && r.project_id !== projectFilter) {
        return false
      }
      if (!query.trim()) return true
      const q = query.toLowerCase()
      return (
        (r.filename || '').toLowerCase().includes(q) ||
        (r.id || '').toLowerCase().includes(q) ||
        (r.project_name || '').toLowerCase().includes(q)
      )
    })
  }, [reports, query, severityFilter, projectFilter])

  async function handleDownload(r) {
    setBusyId(r.id)
    setActionError('')
    try {
      await downloadSavedReportPdf(r.id, r.filename)
    } catch (err) {
      setActionError(friendlyError(err, 'PDF download failed.'))
    } finally {
      setBusyId(null)
    }
  }

  async function handleConfirmDelete() {
    if (!pendingDelete) return
    setBusyId(pendingDelete.id)
    setActionError('')
    try {
      await deleteSavedReport(pendingDelete.id)
      await refreshReportList()
    } catch (err) {
      setActionError(friendlyError(err, 'Failed to delete report.'))
    } finally {
      setBusyId(null)
      setPendingDelete(null)
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Reports"
        description="Persisted audit artifacts and downloadable PDF security assessment reports."
      />

      {error && <ErrorBanner message={error} />}
      {actionError && (
        <ErrorBanner message={actionError} onRetry={() => setActionError('')} />
      )}

      {/* Filter and Search Bar */}
      {!loading && reports.length > 0 && (
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Search reports by filename, report ID, or project…"
              className="input pl-9 text-xs"
            />
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {projects.length > 0 && (
              <select
                value={projectFilter}
                onChange={e => setProjectFilter(e.target.value)}
                className="input w-auto text-xs py-2 px-3"
              >
                <option value="all">All Projects</option>
                {projects.map(p => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            )}

            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              className="input w-auto text-xs py-2 px-3"
            >
              <option value="all">All Severities</option>
              {SEVERITY_ORDER.slice(0, 4).map(s => (
                <option key={s} value={s}>
                  {SEVERITY_META[s].label}
                </option>
              ))}
            </select>
          </div>
        </div>
      )}

      {/* Reports Table Card */}
      <div className="card p-0 overflow-hidden border-slate-200 dark:border-slate-800">
        {loading ? (
          <div className="p-6 space-y-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <CardSkeleton key={i} lines={1} />
            ))}
          </div>
        ) : reports.length === 0 ? (
          <div className="p-4">
            <EmptyState
              icon={FileText}
              title="No security reports generated yet"
              description="Analyze an infrastructure configuration file to automatically compile and store an audit report."
              actionLabel="Run First Analysis"
              actionTo="/analyze?new=1"
            />
          </div>
        ) : filtered.length === 0 ? (
          <div className="py-12 text-center text-xs text-slate-500 dark:text-slate-400">
            No reports match your search or filter.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead>
                <tr className="bg-slate-50/70 dark:bg-slate-950/70 border-b border-slate-200 dark:border-slate-800 text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-4">Configuration &amp; ID</th>
                  <th className="py-3 px-4">Workspace Project</th>
                  <th className="py-3 px-4">Analyzed</th>
                  <th className="py-3 px-4">Resources</th>
                  <th className="py-3 px-4">Findings</th>
                  <th className="py-3 px-4">Risk Posture</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {filtered.map(r => (
                  <tr
                    key={r.id}
                    className="hover:bg-slate-50/80 dark:hover:bg-slate-800/60 transition-colors cursor-pointer"
                    onClick={() => navigate(`/analyze?id=${r.id}`)}
                  >
                    <td className="py-3 px-4">
                      <p className="text-slate-900 dark:text-slate-100 font-bold font-mono text-xs">
                        {r.filename}
                      </p>
                      <p className="text-[11px] text-blue-600 dark:text-blue-400 font-mono mt-0.5">
                        {r.id}
                      </p>
                    </td>

                    <td className="py-3 px-4">
                      <span className="text-slate-700 dark:text-slate-300 font-semibold truncate block max-w-[180px]">
                        {r.project_name || 'Primary Infrastructure'}
                      </span>
                    </td>

                    <td className="py-3 px-4 text-slate-500 dark:text-slate-400 whitespace-nowrap">
                      {formatDateTime(r.created_at)}
                    </td>

                    <td className="py-3 px-4 font-mono font-bold text-slate-700 dark:text-slate-300">
                      {r.resource_count}
                    </td>

                    <td className="py-3 px-4">
                      <span className="font-black text-slate-900 mr-1">
                        {r.findings_count}
                      </span>
                      <span className="text-slate-500">
                        finding{r.findings_count !== 1 ? 's' : ''}
                      </span>
                    </td>

                    <td className="py-3 px-4">
                      {isRealSeverity(r.overall_risk_level) ? (
                        <SeverityBadge severity={r.overall_risk_level} />
                      ) : (
                        <span className="text-[11px] text-slate-400">Not assessed</span>
                      )}
                    </td>

                    <td className="py-3 px-4 text-right" onClick={e => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => navigate(`/analyze?id=${r.id}`)}
                          className="icon-btn hover:text-blue-600 hover:bg-blue-50"
                          title="Open Report in Workbench"
                        >
                          <ExternalLink className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDownload(r)}
                          disabled={busyId === r.id}
                          className="icon-btn hover:text-blue-600 hover:bg-blue-50"
                          title="Download PDF Security Report"
                        >
                          <FileDown className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => setPendingDelete(r)}
                          className="icon-btn hover:text-rose-600 hover:bg-rose-50"
                          title="Delete Report"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={!!pendingDelete}
        title="Delete this security report?"
        message={
          pendingDelete &&
          `This permanently removes "${pendingDelete.filename}" (${pendingDelete.id}) from the database. This action cannot be undone.`
        }
        confirmLabel="Delete Report"
        busy={busyId === pendingDelete?.id}
        onConfirm={handleConfirmDelete}
        onCancel={() => setPendingDelete(null)}
      />
    </div>
  )
}
