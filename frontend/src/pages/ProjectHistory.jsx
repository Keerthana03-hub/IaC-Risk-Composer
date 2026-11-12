/**
 * ProjectHistory.jsx
 * -------------------
 * Timeline view of every completed analysis run (GET /api/reports), grouped
 * by day ("Today" / "Yesterday" / date). Clicking an entry reopens that exact
 * run in the IaC Analysis workbench.
 */

import React, { useMemo, useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Search, FileDown, Trash2, History as HistoryIcon, FileCode2 } from 'lucide-react'

import { deleteSavedReport, downloadSavedReportPdf } from '../api'
import { useAnalysis } from '../context/AnalysisContext'
import { dayLabel, formatTime } from '../utils/format'
import { isRealSeverity } from '../utils/risk'
import { friendlyError } from '../utils/errors'

import PageHeader from '../components/common/PageHeader'
import ErrorBanner from '../components/common/ErrorBanner'
import EmptyState from '../components/common/EmptyState'
import SeverityBadge from '../components/common/SeverityBadge'
import ConfirmDialog from '../components/common/ConfirmDialog'
import { CardSkeleton } from '../components/common/Skeleton'

export default function ProjectHistory() {
  const navigate = useNavigate()
  const { reports, loading, error, refreshReportList } = useAnalysis()
  const [search, setSearch] = useState('')
  const [busyId, setBusyId] = useState(null)
  const [actionError, setActionError] = useState('')
  const [pendingDelete, setPendingDelete] = useState(null)

  const filtered = reports.filter(r =>
    (r.filename || '').toLowerCase().includes(search.toLowerCase()) ||
    (r.id || '').toLowerCase().includes(search.toLowerCase()))

  const groups = useMemo(() => {
    const map = new Map()
    for (const r of filtered) {
      const label = dayLabel(r.created_at)
      if (!map.has(label)) map.set(label, [])
      map.get(label).push(r)
    }
    return [...map.entries()]
  }, [filtered])

  async function handleDownload(r) {
    setBusyId(r.id); setActionError('')
    try { await downloadSavedReportPdf(r.id, r.filename) }
    catch (err) { setActionError(friendlyError(err, 'PDF download failed.')) }
    finally { setBusyId(null) }
  }

  async function handleConfirmDelete() {
    if (!pendingDelete) return
    setBusyId(pendingDelete.id); setActionError('')
    try { await deleteSavedReport(pendingDelete.id); await refreshReportList() }
    catch (err) { setActionError(friendlyError(err, 'Delete failed.')) }
    finally { setBusyId(null); setPendingDelete(null) }
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Project History" description="Timeline of every completed Infrastructure-as-Code analysis." />

      {error && <ErrorBanner message={error} />}
      {actionError && <ErrorBanner message={actionError} onRetry={() => setActionError('')} />}

      {!loading && reports.length > 0 && (
        <div className="relative">
          <Search className="h-4 w-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search history by filename or report ID…" className="input pl-9 font-mono" />
        </div>
      )}

      {loading ? (
        <div className="space-y-3">{Array.from({ length: 3 }).map((_, i) => <CardSkeleton key={i} lines={2} />)}</div>
      ) : reports.length === 0 ? (
        <div className="card">
          <EmptyState icon={HistoryIcon} title="No project history yet" description="Every Terraform file you analyze is automatically logged here." actionLabel="Run Your First Analysis" actionTo="/analyze?new=1" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="card text-center py-10 text-sm text-slate-500">No runs match your search.</div>
      ) : (
        <div className="space-y-8">
          {groups.map(([label, runs]) => (
            <div key={label}>
              <h3 className="eyebrow mb-3">{label}</h3>
              <div className="relative pl-6 space-y-4 before:absolute before:left-[5px] before:top-2 before:bottom-2 before:w-px before:bg-surface-700">
                {runs.map(r => (
                  <div key={r.id} className="relative">
                    <span className="absolute -left-6 top-4 h-2.5 w-2.5 rounded-full bg-cyber-500 ring-4 ring-surface-900" />
                    <button
                      onClick={() => navigate(`/analyze?id=${r.id}`)}
                      className="w-full text-left card card-hover flex items-center gap-4"
                    >
                      <div className="h-10 w-10 rounded-lg bg-surface-700/70 border border-surface-600 flex items-center justify-center flex-shrink-0">
                        <FileCode2 className="h-5 w-5 text-cyber-400" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-semibold text-white font-mono truncate">{r.filename}</p>
                        <p className="text-xs text-slate-500 mt-0.5">
                          {formatTime(r.created_at)} · {r.resource_count} resource{r.resource_count !== 1 ? 's' : ''} · {r.findings_count} finding{r.findings_count !== 1 ? 's' : ''}
                        </p>
                      </div>
                      {isRealSeverity(r.overall_risk_level) && <SeverityBadge severity={r.overall_risk_level} />}
                      <div className="flex items-center gap-1 flex-shrink-0" onClick={e => e.stopPropagation()}>
                        <button onClick={() => handleDownload(r)} disabled={busyId === r.id} className="icon-btn" title="Download PDF"><FileDown className="h-4 w-4" /></button>
                        <button onClick={() => setPendingDelete(r)} className="icon-btn hover:text-red-400" title="Delete"><Trash2 className="h-4 w-4" /></button>
                      </div>
                    </button>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      <ConfirmDialog
        open={!!pendingDelete}
        title="Delete this run?"
        message={pendingDelete && `This permanently deletes "${pendingDelete.filename}" (${pendingDelete.id}) from the database. This cannot be undone.`}
        confirmLabel="Delete"
        busy={busyId === pendingDelete?.id}
        onConfirm={handleConfirmDelete}
        onCancel={() => setPendingDelete(null)}
      />
    </div>
  )
}
