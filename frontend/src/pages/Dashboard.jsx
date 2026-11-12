/**
 * Dashboard.jsx
 * --------------
 * Modern, personalized developer security dashboard.
 * - Personalized greeting: "Good morning / afternoon, [Developer Name]"
 * - Workspace overview cards (Projects, Analyses, Threats, Avg Security Score)
 * - Security posture score ring & severity breakdown
 * - Recent Projects cards with [Open Project] to continue work
 * - Recent Analyses table with view & PDF download
 * - Recent Findings (high/critical vulnerabilities)
 * - Empty states when no data exists yet with prominent CTA
 */

import React, { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Boxes,
  ShieldAlert,
  Flame,
  TriangleAlert,
  ScanSearch,
  Plus,
  FolderGit2,
  ArrowRight,
  ExternalLink,
  FileDown,
  Sparkles,
  ShieldCheck,
  Clock,
  Layers,
} from 'lucide-react'

import { downloadSavedReportPdf, getDashboardStats } from '../api'
import { useAuth } from '../context/AuthContext'
import { useAnalysis } from '../context/AnalysisContext'
import {
  computeSecurityScore,
  countBySeverity,
  groupThreatsByResource,
  isRealSeverity,
  normalizeSeverity,
  resourceTypeCounts,
} from '../utils/risk'
import { formatDateTime, timeAgo } from '../utils/format'
import { friendlyError } from '../utils/errors'

import PageHeader from '../components/common/PageHeader'
import ErrorBanner from '../components/common/ErrorBanner'
import EmptyState from '../components/common/EmptyState'
import StatCard from '../components/dashboard/StatCard'
import SecurityScoreRing from '../components/dashboard/SecurityScoreRing'
import RiskDistributionChart from '../components/dashboard/RiskDistributionChart'
import ResourceTypeChart from '../components/dashboard/ResourceTypeChart'
import ThreatsByResourceChart from '../components/dashboard/ThreatsByResourceChart'
import SeverityBadge from '../components/common/SeverityBadge'

export default function Dashboard() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const {
    result,
    reports,
    projects,
    selectReport,
    selectProject,
    loading: analysisLoading,
  } = useAnalysis()

  const [stats, setStats] = useState(null)
  const [statsError, setStatsError] = useState('')
  const [statsLoading, setStatsLoading] = useState(true)
  const [downloadingId, setDownloadingId] = useState(null)

  useEffect(() => {
    setStatsLoading(true)
    getDashboardStats()
      .then(setStats)
      .catch(err => setStatsError(friendlyError(err, 'Unable to load dashboard metrics.')))
      .finally(() => setStatsLoading(false))
  }, [reports])

  // Personalized time-of-day greeting
  const hour = new Date().getHours()
  const greeting =
    hour < 12 ? 'Good morning' : hour < 17 ? 'Good afternoon' : 'Good evening'
  const developerName = user?.full_name ? user.full_name.split(' ')[0] : user?.username || 'Developer'

  const posture = result ? computeSecurityScore(result) : null
  const counts = result
    ? countBySeverity(result.threat_findings || [])
    : { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  const resourceTypes = result ? resourceTypeCounts(result) : []
  const byResource = result ? groupThreatsByResource(result.threat_findings || []) : []

  async function handleDownloadPdf(e, rep) {
    e.stopPropagation()
    setDownloadingId(rep.id)
    try {
      await downloadSavedReportPdf(rep.id, rep.filename)
    } catch (err) {
      alert(friendlyError(err, 'Download failed.'))
    } finally {
      setDownloadingId(null)
    }
  }

  return (
    <div className="space-y-6">
      {/* Personalized Welcome Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-gradient-to-r from-blue-600 via-blue-700 to-indigo-800 text-white rounded-2xl p-6 sm:p-8 shadow-sm relative overflow-hidden">
        <div className="absolute -right-10 -bottom-10 w-64 h-64 bg-white/10 rounded-full blur-2xl pointer-events-none" />
        <div className="relative z-10">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider bg-white/15 px-2.5 py-0.5 rounded-full text-blue-100 font-mono">
              {user?.organization || 'Developer Workspace'}
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight">
            {greeting}, {developerName}
          </h1>
          <p className="text-blue-100 text-xs sm:text-sm mt-1 max-w-xl leading-relaxed">
            Here is the security posture of your infrastructure workspaces and automated threat models.
          </p>
        </div>
        <div className="relative z-10 flex items-center gap-3 flex-shrink-0">
          <Link
            to="/analyze?new=1"
            className="inline-flex items-center justify-center gap-2 bg-white text-blue-700 hover:bg-blue-50 font-bold px-4 py-2.5 rounded-xl shadow transition-all duration-150 active:scale-95 text-xs sm:text-sm"
          >
            <Plus className="h-4 w-4" />
            <span>New Analysis</span>
          </Link>
          <Link
            to="/projects"
            className="inline-flex items-center justify-center gap-2 bg-white/10 hover:bg-white/20 text-white border border-white/20 font-semibold px-4 py-2.5 rounded-xl transition-all duration-150 text-xs sm:text-sm"
          >
            <FolderGit2 className="h-4 w-4" />
            <span className="hidden sm:inline">All Projects</span>
          </Link>
        </div>
      </div>

      {statsError && <ErrorBanner message={statsError} />}

      {/* Overview Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={FolderGit2}
          label="Active Projects"
          value={projects.length}
          sub="Workspace projects"
          tone="cyber"
          loading={statsLoading}
        />
        <StatCard
          icon={ScanSearch}
          label="Total Analyses"
          value={stats?.total_scans ?? reports.length}
          sub="Persisted scan runs"
          loading={statsLoading}
        />
        <StatCard
          icon={ShieldAlert}
          label="Threats Detected"
          value={stats?.open_findings ?? 0}
          sub="Total misconfigurations"
          tone={stats?.open_findings > 0 ? 'critical' : 'good'}
          loading={statsLoading}
        />
        <StatCard
          icon={Flame}
          label="Avg. Inherent Risk"
          value={stats?.avg_risk_score != null ? `${stats.avg_risk_score} / 25` : '—'}
          sub={stats?.avg_risk_score != null ? 'Across assessed findings' : 'Awaiting scans'}
          tone={stats?.avg_risk_score >= 15 ? 'critical' : stats?.avg_risk_score >= 8 ? 'high' : 'good'}
          loading={statsLoading}
        />
      </div>

      {/* Recent Projects Section (Section 5) */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-slate-900 tracking-tight">Recent Projects</h2>
            <p className="text-xs text-slate-500">Pick up where you left off across your active workspaces.</p>
          </div>
          <Link to="/projects" className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1">
            View all ({projects.length}) <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>

        {projects.length === 0 ? (
          <div className="card">
            <EmptyState
              icon={FolderGit2}
              title="No projects yet"
              description="Start by creating a project or uploading an IaC configuration."
              actionLabel="Create First Project"
              actionTo="/projects"
            />
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {projects.slice(0, 3).map((p) => {
              const hasAnalysis = p.analyses_count > 0
              return (
                <div
                  key={p.id}
                  className="card card-hover flex flex-col justify-between p-5 border border-slate-200/90 dark:border-slate-800 relative"
                >
                  <div>
                    <div className="flex items-start justify-between gap-3 mb-2">
                      <div className="flex items-center gap-2.5 min-w-0">
                        <div className="h-9 w-9 rounded-xl bg-blue-50 dark:bg-blue-950/60 border border-blue-100 dark:border-blue-900/60 flex items-center justify-center flex-shrink-0 text-blue-600 dark:text-blue-400">
                          <FolderGit2 className="h-5 w-5" />
                        </div>
                        <div className="min-w-0">
                          <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 truncate leading-snug">
                            {p.name}
                          </h3>
                          <span className="text-[11px] text-slate-500 dark:text-slate-400 flex items-center gap-1 mt-0.5">
                            <Clock className="h-3 w-3" />
                            {p.last_analyzed ? timeAgo(p.last_analyzed) : 'Not analyzed yet'}
                          </span>
                        </div>
                      </div>
                      {isRealSeverity(p.overall_risk_level) && (
                        <SeverityBadge severity={p.overall_risk_level} />
                      )}
                    </div>

                    <p className="text-xs text-slate-600 dark:text-slate-400 line-clamp-2 mt-2 leading-relaxed">
                      {p.description || 'Infrastructure workspace container.'}
                    </p>
                  </div>

                  <div className="mt-5 pt-3.5 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-xs">
                    <div className="text-slate-500 dark:text-slate-400">
                      {hasAnalysis ? (
                        <span>
                          <strong className="text-slate-900 dark:text-slate-100 font-bold">{p.findings_count}</strong> finding{p.findings_count !== 1 ? 's' : ''}
                          {p.critical_count > 0 && (
                            <span className="text-rose-600 dark:text-rose-400 font-bold ml-1">({p.critical_count} critical)</span>
                          )}
                        </span>
                      ) : (
                        <span className="italic text-slate-400 dark:text-slate-500">Ready for scan</span>
                      )}
                    </div>

                    <button
                      onClick={() => {
                        selectProject(p.id)
                        navigate(p.latest_analysis_id ? `/analyze?id=${p.latest_analysis_id}` : `/analyze?new=1&project_id=${p.id}`)
                      }}
                      className="btn-ghost text-xs py-1.5 px-3 font-semibold text-blue-600 dark:text-blue-400 border-blue-200 dark:border-blue-900/60 hover:bg-blue-50 dark:hover:bg-blue-950/40"
                    >
                      {hasAnalysis ? 'Open Project' : 'Start Scan'}
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Posture & Analysis Deep-Dive Section */}
      {!analysisLoading && !result ? (
        <div className="card">
          <EmptyState
            icon={ScanSearch}
            title="No analyses in this workspace yet"
            description="Upload your Terraform configuration to begin infrastructure security scanning."
            actionLabel="Start New Analysis"
            actionTo="/analyze?new=1"
          />
        </div>
      ) : (
        <>
          {/* Posture ring + severity stats */}
          <div className="grid grid-cols-1 lg:grid-cols-[auto,1fr] gap-4">
            <div className="card flex flex-col items-center justify-center py-8 px-8 sm:px-12 bg-white dark:bg-slate-900 border-slate-200/90 dark:border-slate-800">
              <SecurityScoreRing
                score={posture?.score ?? null}
                band={posture?.band}
                label={posture?.label}
              />
              {result && (
                <div className="mt-5 text-center">
                  <p className="text-[11px] text-slate-400 dark:text-slate-500 font-medium">Active Analysis</p>
                  <p className="text-xs font-mono font-bold text-blue-600 dark:text-blue-400 truncate max-w-[200px]">
                    {result.filename}
                  </p>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                    {formatDateTime(result.created_at)}
                  </p>
                </div>
              )}
            </div>

            <div className="space-y-4">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <StatCard label="Critical" value={counts.critical} tone="critical" icon={TriangleAlert} />
                <StatCard label="High" value={counts.high} tone="high" icon={TriangleAlert} />
                <StatCard label="Medium" value={counts.medium} tone="default" icon={TriangleAlert} />
                <StatCard label="Low" value={counts.low} tone="good" icon={TriangleAlert} />
              </div>
              <ResourceTypeChart data={resourceTypes.slice(0, 6)} />
            </div>
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <RiskDistributionChart counts={counts} />
            <ThreatsByResourceChart rows={byResource} />
          </div>

          {/* Recent Analyses Table */}
          <div className="card p-0 overflow-hidden border-slate-200 dark:border-slate-800">
            <div className="p-4 sm:p-5 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between flex-wrap gap-2">
              <div>
                <h3 className="section-title">Recent Workspace Analyses</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">Completed infrastructure scan results and reports.</p>
              </div>
              <Link to="/reports" className="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 flex items-center gap-1">
                View all reports <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </div>

            {reports.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 dark:text-slate-400">No analyses run yet.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead>
                    <tr className="bg-slate-50/70 dark:bg-slate-950/70 border-b border-slate-200/80 dark:border-slate-800 text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                      <th className="py-3 px-4">Configuration</th>
                      <th className="py-3 px-4">Analyzed</th>
                      <th className="py-3 px-4">Resources</th>
                      <th className="py-3 px-4">Findings</th>
                      <th className="py-3 px-4">Highest Severity</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {reports.slice(0, 5).map((r) => (
                      <tr
                        key={r.id}
                        onClick={() => navigate(`/analyze?id=${r.id}`)}
                        className="hover:bg-slate-50/80 dark:hover:bg-slate-800/60 cursor-pointer transition-colors"
                      >
                        <td className="py-3 px-4">
                          <p className="font-semibold text-slate-900 dark:text-slate-100 font-mono">{r.filename}</p>
                          <p className="text-[11px] text-slate-400 dark:text-slate-500 font-mono">{r.id}</p>
                        </td>
                        <td className="py-3 px-4 text-slate-500 dark:text-slate-400 whitespace-nowrap">
                          {formatDateTime(r.created_at)}
                        </td>
                        <td className="py-3 px-4 font-mono font-medium text-slate-700 dark:text-slate-300">
                          {r.resource_count}
                        </td>
                        <td className="py-3 px-4">
                          <span className="font-bold text-slate-900 dark:text-slate-100 mr-1">{r.findings_count}</span>
                          <span className="text-slate-500 dark:text-slate-400">issue{r.findings_count !== 1 ? 's' : ''}</span>
                        </td>
                        <td className="py-3 px-4">
                          {isRealSeverity(r.overall_risk_level) ? (
                            <SeverityBadge severity={r.overall_risk_level} />
                          ) : (
                            <span className="text-[11px] text-slate-400 dark:text-slate-500">Not assessed</span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              onClick={() => navigate(`/analyze?id=${r.id}`)}
                              className="icon-btn hover:text-blue-600 dark:hover:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-950/40"
                              title="View in Workbench"
                            >
                              <ExternalLink className="h-4 w-4" />
                            </button>
                            <button
                              onClick={(e) => handleDownloadPdf(e, r)}
                              disabled={downloadingId === r.id}
                              className="icon-btn hover:text-blue-600 hover:bg-blue-50"
                              title="Download PDF"
                            >
                              <FileDown className="h-4 w-4" />
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
        </>
      )}

      {/* Quick Launch Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Link to="/analyze?new=1" className="card card-hover group flex items-center gap-4 p-5">
          <div className="h-11 w-11 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center flex-shrink-0 text-blue-600">
            <Plus className="h-5 w-5" />
          </div>
          <div>
            <h3 className="font-bold text-slate-900 text-sm group-hover:text-blue-600 transition-colors">
              New IaC Scan
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">Upload Terraform for threat analysis.</p>
          </div>
        </Link>

        <Link to="/infrastructure" className="card card-hover group flex items-center gap-4 p-5">
          <div className="h-11 w-11 rounded-xl bg-indigo-50 border border-indigo-100 flex items-center justify-center flex-shrink-0 text-indigo-600">
            <Layers className="h-5 w-5" />
          </div>
          <div>
            <h3 className="font-bold text-slate-900 text-sm group-hover:text-blue-600 transition-colors">
              Infrastructure Map
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">Explore visual topology & dependencies.</p>
          </div>
        </Link>

        <Link to="/threats" className="card card-hover group flex items-center gap-4 p-5">
          <div className="h-11 w-11 rounded-xl bg-rose-50 border border-rose-100 flex items-center justify-center flex-shrink-0 text-rose-600">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div>
            <h3 className="font-bold text-slate-900 text-sm group-hover:text-blue-600 transition-colors">
              Threat Findings
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">Review actionable safe code fixes.</p>
          </div>
        </Link>
      </div>
    </div>
  )
}
