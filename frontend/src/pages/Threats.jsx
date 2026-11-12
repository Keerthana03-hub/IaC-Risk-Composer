/**
 * Threats.jsx
 * ------------
 * Security Threats & Risk Findings (Section 10).
 * Displays threats detected across the developer's infrastructure configuration.
 * Includes threat count overview cards, search, severity filters, resource filters,
 * and detailed remediation drawers.
 */

import React, { useMemo, useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  Search,
  ShieldAlert,
  TriangleAlert,
  Filter,
  Layers,
  FolderGit2,
} from 'lucide-react'

import { useAnalysis } from '../context/AnalysisContext'
import PageHeader from '../components/common/PageHeader'
import ErrorBanner from '../components/common/ErrorBanner'
import EmptyState from '../components/common/EmptyState'
import { CardSkeleton } from '../components/common/Skeleton'
import ThreatCard from '../components/threats/ThreatCard'
import ThreatDetailPanel from '../components/threats/ThreatDetailPanel'
import { buildThreatViews } from '../utils/threats'
import { SEVERITY_ORDER, SEVERITY_META, countBySeverity } from '../utils/risk'
import { formatDateTime } from '../utils/format'

export default function Threats() {
  const [searchParams] = useSearchParams()
  const {
    result,
    loading,
    error,
    reports,
    projects,
    currentProjectId,
    selectProject,
    selectReport,
    currentId,
  } = useAnalysis()

  const [query, setQuery] = useState(() => searchParams.get('q') || '')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [resourceFilter, setResourceFilter] = useState('all')
  const [open, setOpen] = useState(null)

  useEffect(() => {
    const q = searchParams.get('q')
    if (q) setQuery(q)
  }, [searchParams])

  const allViews = useMemo(() => buildThreatViews(result || {}), [result])
  const counts = useMemo(
    () => countBySeverity(result?.threat_findings || []),
    [result]
  )

  // Extract unique resources in this analysis for filter
  const resourceOptions = useMemo(() => {
    const set = new Set()
    for (const v of allViews) {
      if (v.resourceId) set.add(v.resourceId)
    }
    return Array.from(set).sort()
  }, [allViews])

  const filteredViews = allViews.filter(v => {
    if (severityFilter !== 'all' && v.severity !== severityFilter) return false
    if (
      statusFilter !== 'all' &&
      v.finding.detection_status?.toLowerCase() !== statusFilter.toLowerCase()
    ) {
      return false
    }
    if (resourceFilter !== 'all' && v.resourceId !== resourceFilter) {
      return false
    }
    if (!query.trim()) return true
    const q = query.toLowerCase()
    return (
      v.title?.toLowerCase().includes(q) ||
      v.resourceId?.toLowerCase().includes(q) ||
      v.description?.toLowerCase().includes(q) ||
      v.explanation?.why_it_matters?.toLowerCase().includes(q)
    )
  })

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threats"
        description="Security threats and misconfigurations detected across your infrastructure."
        actions={
          <div className="flex items-center gap-2 flex-wrap">
            {projects.length > 0 && (
              <select
                value={currentProjectId || ''}
                onChange={e => selectProject(e.target.value)}
                className="input w-auto text-xs font-semibold py-2 px-3 max-w-[200px]"
                title="Select Project"
              >
                {projects.map(p => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            )}

            {reports.length > 0 && (
              <select
                value={currentId || ''}
                onChange={e => selectReport(e.target.value)}
                className="input w-auto text-xs font-medium py-2 px-3 max-w-[220px]"
                title="Select Analysis Run"
              >
                {reports.map(r => (
                  <option key={r.id} value={r.id}>
                    {r.filename} &middot; {formatDateTime(r.created_at)}
                  </option>
                ))}
              </select>
            )}
          </div>
        }
      />

      {error && <ErrorBanner message={error} />}

      {/* Threat Counts Overview Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="card p-4 border-l-4 border-l-rose-500 bg-white dark:bg-slate-900 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-bold text-rose-700 dark:text-rose-400 uppercase tracking-wider block">
              Critical
            </span>
            <span className="text-2xl font-black text-rose-700 dark:text-rose-400 tracking-tight">
              {counts.critical}
            </span>
          </div>
          <TriangleAlert className="h-6 w-6 text-rose-500/30" />
        </div>

        <div className="card p-4 border-l-4 border-l-orange-500 bg-white dark:bg-slate-900 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-bold text-orange-700 dark:text-orange-400 uppercase tracking-wider block">
              High
            </span>
            <span className="text-2xl font-black text-orange-700 dark:text-orange-400 tracking-tight">
              {counts.high}
            </span>
          </div>
          <TriangleAlert className="h-6 w-6 text-orange-500/30" />
        </div>

        <div className="card p-4 border-l-4 border-l-amber-500 bg-white dark:bg-slate-900 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-bold text-amber-700 dark:text-amber-400 uppercase tracking-wider block">
              Medium
            </span>
            <span className="text-2xl font-black text-amber-700 dark:text-amber-400 tracking-tight">
              {counts.medium}
            </span>
          </div>
          <TriangleAlert className="h-6 w-6 text-amber-500/30" />
        </div>

        <div className="card p-4 border-l-4 border-l-emerald-500 bg-white dark:bg-slate-900 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-bold text-emerald-700 dark:text-emerald-400 uppercase tracking-wider block">
              Low
            </span>
            <span className="text-2xl font-black text-emerald-700 dark:text-emerald-400 tracking-tight">
              {counts.low}
            </span>
          </div>
          <TriangleAlert className="h-6 w-6 text-emerald-500/30" />
        </div>
      </div>

      {loading ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <CardSkeleton key={i} lines={4} />
          ))}
        </div>
      ) : !result ? (
        <div className="card">
          <EmptyState
            icon={ShieldAlert}
            title="No analysis selected"
            description="Run or select an infrastructure analysis to inspect security threats."
            actionLabel="Start New Analysis"
            actionTo="/analyze?new=1"
          />
        </div>
      ) : allViews.length === 0 ? (
        <div className="card">
          <EmptyState
            icon={ShieldAlert}
            title="No threats detected"
            description={`${result.filename} passed all security rules. Zero findings detected.`}
          />
        </div>
      ) : (
        <>
          {/* Filters & Search Row */}
          <div className="flex flex-col md:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Search findings by title, resource ID, or description…"
                className="input pl-9 text-xs"
              />
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              {/* Severity Filter Buttons */}
              <div className="flex gap-1 bg-slate-100 dark:bg-slate-800 p-1 rounded-lg">
                <button
                  onClick={() => setSeverityFilter('all')}
                  className={`text-xs font-bold px-2.5 py-1 rounded-md transition-colors ${
                    severityFilter === 'all'
                      ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs'
                      : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
                  }`}
                >
                  All ({allViews.length})
                </button>
                {SEVERITY_ORDER.slice(0, 4).map(s => {
                  const n = allViews.filter(v => v.severity === s).length
                  if (n === 0) return null
                  const active = severityFilter === s
                  return (
                    <button
                      key={s}
                      onClick={() => setSeverityFilter(s)}
                      className={`text-xs font-bold px-2.5 py-1 rounded-md transition-colors ${
                        active
                          ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs'
                          : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
                      }`}
                    >
                      {SEVERITY_META[s].label} ({n})
                    </button>
                  )
                })}
              </div>

              {/* Status Filter */}
              <select
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value)}
                className="input w-auto text-xs py-1.5 px-3"
              >
                <option value="all">All Statuses</option>
                <option value="confirmed">Confirmed</option>
                <option value="needs review">Needs Review</option>
              </select>

              {/* Resource Filter */}
              {resourceOptions.length > 0 && (
                <select
                  value={resourceFilter}
                  onChange={e => setResourceFilter(e.target.value)}
                  className="input w-auto text-xs py-1.5 px-3 max-w-[200px]"
                >
                  <option value="all">All Resources ({resourceOptions.length})</option>
                  {resourceOptions.map(r => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              )}
            </div>
          </div>

          {filteredViews.length === 0 ? (
            <div className="card text-center py-12 text-xs text-slate-500">
              No findings match your selected filter criteria.
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {filteredViews.map((v, i) => (
                <ThreatCard
                  key={v.id}
                  view={v}
                  onOpen={setOpen}
                  style={{ animationDelay: `${Math.min(i, 10) * 30}ms` }}
                />
              ))}
            </div>
          )}
        </>
      )}

      <ThreatDetailPanel view={open} onClose={() => setOpen(null)} />
    </div>
  )
}
