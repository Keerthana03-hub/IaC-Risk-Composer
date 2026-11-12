/**
 * IacAnalysis.jsx
 * ----------------
 * New Security Analysis Workbench.
 * - Project workspace selector
 * - Drag & drop infrastructure file upload
 * - Interactive multi-step progress stepper
 * - Security results tabs:
 *   1. Findings (Threat cards with severity, risk scoring)
 *   2. Risk Explanations (Evidence-grounded explanations)
 *   3. Remediations (Safe code patches with Copy button)
 *   4. Infrastructure & Resources (Interactive Map & declared resource table)
 * - Downloadable PDF Report
 */

import React, { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  FileDown,
  Upload as UploadIcon,
  RotateCcw,
  ClipboardCopy,
  Check,
  AlertTriangle,
  FolderGit2,
  ShieldAlert,
  Boxes,
  FileCode2,
  CheckCircle2,
  Layers,
  Sparkles,
} from 'lucide-react'

import { analyzeTerraformFile, downloadSecurityReport } from '../api'
import { useAnalysis } from '../context/AnalysisContext'

import PageHeader from '../components/common/PageHeader'
import ErrorBanner from '../components/common/ErrorBanner'
import UploadArea from '../components/analysis/UploadArea'
import AnalysisProgress from '../components/analysis/AnalysisProgress'
import SeverityBadge from '../components/common/SeverityBadge'
import ThreatCard from '../components/threats/ThreatCard'
import ThreatDetailPanel from '../components/threats/ThreatDetailPanel'
import InfrastructureMap from '../components/infrastructure/InfrastructureMap'
import { buildThreatViews } from '../utils/threats'
import { formatDateTime } from '../utils/format'
import { friendlyError } from '../utils/errors'
import { normalizeSeverity, isRealSeverity } from '../utils/risk'

function CodeSnippetBox({ code, label }) {
  const [copied, setCopied] = useState(false)
  function handleCopy() {
    if (!code) return
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div className="mt-3 bg-slate-900 text-slate-100 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
      <div className="flex items-center justify-between px-3.5 py-2 bg-slate-800/80 border-b border-slate-700/60 text-xs text-slate-400">
        <span className="font-mono text-slate-300 truncate text-[11px]">
          {label || 'Suggested Terraform Patch'}
        </span>
        <button
          onClick={handleCopy}
          className="hover:text-blue-400 transition-colors font-medium flex items-center gap-1.5 flex-shrink-0"
        >
          {copied ? (
            <>
              <Check className="h-3.5 w-3.5 text-emerald-400" /> Copied
            </>
          ) : (
            <>
              <ClipboardCopy className="h-3.5 w-3.5" /> Copy Patch
            </>
          )}
        </button>
      </div>
      <pre className="p-3.5 text-xs font-mono text-emerald-300 overflow-x-auto leading-relaxed">
        <code>{code}</code>
      </pre>
      <div className="px-3.5 py-2 bg-amber-500/10 border-t border-amber-500/20 text-[11px] text-amber-300 flex items-center gap-1.5 font-medium">
        <AlertTriangle className="h-3.5 w-3.5 text-amber-400 flex-shrink-0" />
        Safe suggestion only — review before applying. User files are never modified automatically.
      </div>
    </div>
  )
}

const TABS = [
  { id: 'overview', label: 'Findings' },
  { id: 'explanations', label: 'Risk Explanations' },
  { id: 'remediations', label: 'Remediations' },
  { id: 'infra', label: 'Infrastructure & Resources' },
]

export default function IacAnalysis() {
  const [searchParams, setSearchParams] = useSearchParams()
  const {
    result,
    projects,
    currentProjectId,
    selectReport,
    setResult,
    loading: ctxLoading,
  } = useAnalysis()

  const [selectedFile, setSelectedFile] = useState(null)
  const [targetProjectId, setTargetProjectId] = useState(() => searchParams.get('project_id') || currentProjectId || '')
  const [analyzing, setAnalyzing] = useState(false)
  const [showUpload, setShowUpload] = useState(searchParams.get('new') === '1')
  const [uploadError, setUploadError] = useState('')
  const [downloading, setDownloading] = useState(false)
  const [reportError, setReportError] = useState('')
  const [activeTab, setActiveTab] = useState('overview')
  const [openThreat, setOpenThreat] = useState(null)

  // Sync project ID when available
  useEffect(() => {
    if (!targetProjectId && currentProjectId) {
      setTargetProjectId(currentProjectId)
    }
  }, [currentProjectId, targetProjectId])

  // Deep link: /analyze?id=... opens a specific historical run
  useEffect(() => {
    const id = searchParams.get('id')
    if (id) selectReport(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams.get('id')])

  function handleFileSelect(file) {
    if (!file.name.toLowerCase().endsWith('.tf')) {
      setUploadError('Please select a Terraform (.tf) configuration file.')
      setSelectedFile(null)
      return
    }
    setUploadError('')
    setSelectedFile(file)
  }

  async function handleAnalyze() {
    if (!selectedFile) return
    setAnalyzing(true)
    setUploadError('')
    try {
      const data = await analyzeTerraformFile(selectedFile, targetProjectId || null)
      setResult(data)
      if (data.id) setSearchParams({ id: data.id })
      setActiveTab('overview')
      setShowUpload(false)
      setSelectedFile(null)
    } catch (err) {
      setUploadError(friendlyError(err, 'Unable to complete security analysis.'))
    } finally {
      setAnalyzing(false)
    }
  }

  async function handleDownloadReport() {
    if (!result) return
    setDownloading(true)
    setReportError('')
    try {
      await downloadSecurityReport(result)
    } catch (err) {
      setReportError(friendlyError(err, 'Unable to generate the PDF security report.'))
    } finally {
      setDownloading(false)
    }
  }

  const findings = result?.threat_findings || []
  const riskSummary = result?.risk_summary || {}
  const explanations = result?.risk_explanations || []
  const remediations = result?.remediations || []
  const infraMap = result?.infrastructure_map || { nodes: [], edges: [] }
  const resources = result?.resources || []
  const threatViews = buildThreatViews(result || {})

  const totalFindings = riskSummary.total_findings ?? findings.length
  const confirmedCount =
    riskSummary.confirmed_findings ??
    findings.filter(f => f.detection_status === 'Confirmed').length
  const needsReviewCount =
    riskSummary.needs_review_findings ??
    findings.filter(f => f.detection_status === 'Needs Review').length
  const overallRisk =
    riskSummary.overall_risk_level ||
    (result && findings.length === 0 ? 'Low' : null)

  const uploadPanel = (
    <div className="card space-y-5 p-6 border-slate-200">
      {/* Target Project Selector */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 bg-slate-50 border border-slate-200/80 rounded-xl">
        <div className="flex items-center gap-2.5">
          <FolderGit2 className="h-4 w-4 text-blue-600" />
          <div>
            <span className="text-xs font-bold text-slate-800 block">Workspace Project</span>
            <span className="text-[11px] text-slate-500">Associate scan results with an existing workspace</span>
          </div>
        </div>

        {projects.length > 0 && (
          <select
            value={targetProjectId}
            onChange={e => setTargetProjectId(e.target.value)}
            className="input w-auto text-xs font-semibold py-1.5 px-3 max-w-[240px]"
          >
            {projects.map(p => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        )}
      </div>

      <UploadArea
        selectedFile={selectedFile}
        onSelect={handleFileSelect}
        onClear={() => setSelectedFile(null)}
        error={uploadError}
      />

      <div className="flex justify-end gap-3 pt-2 border-t border-slate-100">
        {result && (
          <button
            onClick={() => setShowUpload(false)}
            className="btn-ghost text-xs font-semibold py-2 px-4"
          >
            Cancel
          </button>
        )}
        <button
          onClick={handleAnalyze}
          disabled={analyzing || !selectedFile}
          className="btn-primary min-w-44 text-xs font-semibold py-2 px-4 shadow-sm"
        >
          {analyzing ? 'Analyzing Infrastructure…' : 'Analyze Infrastructure'}
        </button>
      </div>
    </div>
  )

  return (
    <div className="space-y-6">
      <PageHeader
        title="New Security Analysis"
        description="Upload your infrastructure configuration to identify security risks, misconfigurations, and potential threats."
        actions={
          result &&
          !showUpload && (
            <div className="flex items-center gap-2 flex-wrap">
              <button
                onClick={handleDownloadReport}
                disabled={downloading}
                className="btn-primary text-xs py-2 px-3 shadow-sm font-semibold"
              >
                <FileDown className="h-4 w-4" />
                {downloading ? 'Compiling PDF…' : 'Download PDF Report'}
              </button>
              <button
                onClick={() => setShowUpload(true)}
                className="btn-ghost text-xs py-2 px-3 font-semibold"
              >
                <UploadIcon className="h-4 w-4" /> Upload Another File
              </button>
            </div>
          )
        }
      />

      {reportError && <ErrorBanner message={reportError} />}

      {(showUpload || !result) && !analyzing && uploadPanel}
      <AnalysisProgress active={analyzing} />

      {ctxLoading && !result && !analyzing && (
        <div className="card text-center py-12 text-xs text-slate-500">
          Loading security analysis…
        </div>
      )}

      {result && !analyzing && (
        <div className="space-y-6 animate-fade-in">
          {/* Posture Summary Banner */}
          <div className="card border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm p-6">
            <div className="flex items-center justify-between flex-wrap gap-4 border-b border-slate-100 dark:border-slate-800 pb-4 mb-4">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 uppercase tracking-wider font-semibold">
                    Report ID:
                  </span>
                  <span className="font-mono text-xs text-blue-700 dark:text-blue-300 bg-blue-50 dark:bg-blue-950 px-2 py-0.5 rounded border border-blue-200/80 dark:border-blue-800 font-bold">
                    {result.id || 'Current Run'}
                  </span>
                  {result.project_name && (
                    <span className="text-xs text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded font-medium">
                      Project: {result.project_name}
                    </span>
                  )}
                </div>
                <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100 mt-2">
                  <span className="font-mono text-blue-600 dark:text-blue-400">{result.filename}</span>
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  Analyzed {formatDateTime(result.created_at)}
                </p>
              </div>

              {isRealSeverity(overallRisk) && (
                <div className="text-right">
                  <span className="eyebrow block mb-1">Overall Posture</span>
                  <SeverityBadge severity={normalizeSeverity(overallRisk)} size="lg" />
                </div>
              )}
            </div>

            {/* Metrics Row */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              {[
                ['Resources', result.resource_count, 'text-slate-900 dark:text-slate-100'],
                ['Total Findings', totalFindings, 'text-blue-600 dark:text-blue-400'],
                ['Confirmed', confirmedCount, 'text-rose-600 dark:text-rose-400'],
                ['Needs Review', needsReviewCount, 'text-amber-600 dark:text-amber-400'],
                ['Max Inherent Score', riskSummary.highest_inherent_risk_score ?? '—', 'text-orange-600 dark:text-orange-400'],
              ].map(([label, value, cls]) => (
                <div key={label} className="inset-box p-3 bg-slate-50 dark:bg-slate-950/70 border border-slate-200/70 dark:border-slate-800">
                  <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase font-semibold tracking-wider block">
                    {label}
                  </span>
                  <span className={`text-2xl font-black mt-1 block tracking-tight ${cls}`}>
                    {value}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {findings.length === 0 && (
            <div className="text-xs text-emerald-800 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 rounded-xl px-4 py-3 flex items-center gap-2 font-medium">
              <CheckCircle2 className="h-4 w-4 text-emerald-600 dark:text-emerald-400" /> Clean configuration — no security misconfigurations detected in this file.
            </div>
          )}

          {/* Navigation Tabs */}
          <div className="flex items-center gap-1 border-b border-slate-200 dark:border-slate-800 overflow-x-auto">
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                className={`px-4 py-2.5 text-xs font-bold whitespace-nowrap border-b-2 -mb-px transition-colors
                  ${
                    activeTab === t.id
                      ? 'text-blue-600 dark:text-blue-400 border-blue-600 dark:border-blue-400 bg-blue-50/40 dark:bg-blue-950/40 rounded-t-lg'
                      : 'text-slate-500 dark:text-slate-400 border-transparent hover:text-slate-900 dark:hover:text-slate-100 hover:border-slate-300 dark:hover:border-slate-700'
                  }`}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Tab 1: Findings */}
          {activeTab === 'overview' && (
            findings.length === 0 ? (
              <div className="card text-center py-10 text-xs text-slate-500">
                No threat findings identified.
              </div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {threatViews.map((v, i) => (
                  <ThreatCard
                    key={v.id}
                    view={v}
                    onOpen={setOpenThreat}
                    style={{ animationDelay: `${i * 30}ms` }}
                  />
                ))}
              </div>
            )
          )}

          {/* Tab 2: Explanations */}
          {activeTab === 'explanations' && (
            explanations.length === 0 ? (
              <div className="card text-center py-10 text-xs text-slate-500">
                No risk explanations available.
              </div>
            ) : (
              <div className="space-y-4">
                {explanations.map((exp, idx) => (
                  <div key={exp.finding_id || idx} className="card space-y-3 p-5">
                    <div className="flex items-center justify-between flex-wrap gap-2 pb-2 border-b border-slate-100">
                      <span className="font-mono text-xs text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200 font-bold">
                        {exp.finding_id}
                      </span>
                      <span className="text-xs px-2 py-0.5 rounded bg-slate-100 text-slate-600 font-medium">
                        {exp.explanation_status} &middot; {exp.explanation_method}
                      </span>
                    </div>

                    <div>
                      <h4 className="text-xs font-bold text-slate-900 mb-1 uppercase tracking-wider text-[11px] text-slate-500">
                        Summary
                      </h4>
                      <p className="text-xs text-slate-800 leading-relaxed font-medium">
                        {exp.summary}
                      </p>
                    </div>

                    <div>
                      <h4 className="text-xs font-bold text-slate-900 mb-1 uppercase tracking-wider text-[11px] text-slate-500">
                        Why It Matters
                      </h4>
                      <p className="text-xs text-slate-700 leading-relaxed">
                        {exp.why_it_matters}
                      </p>
                    </div>

                    <div>
                      <h4 className="text-xs font-bold text-slate-900 mb-1 uppercase tracking-wider text-[11px] text-slate-500">
                        Evidence
                      </h4>
                      <p className="text-xs text-blue-800 bg-blue-50/50 p-3 rounded-lg border border-blue-100 leading-relaxed font-mono">
                        {exp.evidence_explanation}
                      </p>
                    </div>

                    {exp.uncertainty && (
                      <div className="inset-box p-3 text-xs bg-amber-50/60 border-amber-200">
                        <span className="text-amber-800 font-bold block mb-0.5">
                          Uncertainty &amp; Assumptions
                        </span>
                        <p className="text-amber-700 italic text-[11px]">{exp.uncertainty}</p>
                      </div>
                    )}

                    {exp.recommended_actions?.length > 0 && (
                      <div>
                        <h4 className="text-[11px] font-bold text-slate-700 uppercase tracking-wider mb-1">
                          Recommended Actions
                        </h4>
                        <ul className="list-disc list-inside text-xs text-slate-700 space-y-1">
                          {exp.recommended_actions.map((a, i) => (
                            <li key={i}>{a}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {exp.verification_steps?.length > 0 && (
                      <div>
                        <h4 className="text-[11px] font-bold text-slate-700 uppercase tracking-wider mb-1">
                          Verification Steps
                        </h4>
                        <ul className="list-disc list-inside text-xs text-slate-600 space-y-1">
                          {exp.verification_steps.map((s, i) => (
                            <li key={i}>{s}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )
          )}

          {/* Tab 3: Remediations */}
          {activeTab === 'remediations' && (
            remediations.length === 0 ? (
              <div className="card text-center py-10 text-xs text-slate-500">
                No remediation recommendations generated.
              </div>
            ) : (
              <div className="space-y-4">
                {remediations.map((rem, idx) => (
                  <div key={rem.remediation_id || idx} className="card space-y-3 p-5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-blue-50 text-blue-700 border border-blue-200">
                        {rem.patch_type}
                      </span>
                      <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-amber-50 text-amber-800 border border-amber-200">
                        {rem.remediation_status}
                      </span>
                    </div>

                    <h3 className="text-sm font-bold text-slate-900">{rem.title}</h3>
                    <span className="font-mono text-xs text-slate-500 block">
                      Target: {rem.affected_resource_id}
                    </span>

                    <p className="text-xs text-slate-700 leading-relaxed">{rem.explanation}</p>

                    {rem.suggested_code && (
                      <CodeSnippetBox code={rem.suggested_code} label={rem.affected_resource_id} />
                    )}

                    {rem.recommended_actions?.length > 0 && (
                      <div className="pt-2">
                        <span className="text-[11px] font-bold text-slate-700 uppercase tracking-wider block mb-1">
                          Recommended Steps:
                        </span>
                        <ul className="list-disc list-inside text-xs text-slate-700 space-y-1">
                          {rem.recommended_actions.map((a, i) => (
                            <li key={i}>{a}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 text-xs">
                      {rem.assumptions?.length > 0 && (
                        <div className="inset-box p-3">
                          <span className="text-slate-800 font-bold block mb-1 text-[11px]">
                            Assumptions
                          </span>
                          <ul className="list-disc list-inside text-slate-600 space-y-0.5 text-[11px]">
                            {rem.assumptions.map((a, i) => (
                              <li key={i}>{a}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {rem.validation_steps?.length > 0 && (
                        <div className="inset-box p-3">
                          <span className="text-slate-800 font-bold block mb-1 text-[11px]">
                            Validation Steps
                          </span>
                          <ul className="list-disc list-inside text-slate-600 space-y-0.5 text-[11px]">
                            {rem.validation_steps.map((v, i) => (
                              <li key={i}>{v}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )
          )}

          {/* Tab 4: Infrastructure & Resources */}
          {activeTab === 'infra' && (
            <div className="space-y-6">
              <InfrastructureMap infraMap={infraMap} findings={findings} />

              <div className="card p-0 overflow-hidden">
                <div className="p-4 sm:p-5 border-b border-slate-100 flex items-center justify-between">
                  <h3 className="section-title">Declared Resources</h3>
                  <span className="text-xs font-semibold text-slate-500 bg-slate-100 px-2.5 py-0.5 rounded-full">
                    {resources.length} blocks
                  </span>
                </div>

                {resources.length === 0 ? (
                  <p className="text-xs text-slate-500 p-6">
                    No resource blocks were found in this file.
                  </p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="text-left text-[11px] font-semibold text-slate-500 uppercase tracking-wider bg-slate-50 border-b border-slate-200">
                          <th className="py-2.5 px-4">Resource Type</th>
                          <th className="py-2.5 px-4">Name</th>
                          <th className="py-2.5 px-4">Attributes</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {resources.map((r, i) => (
                          <tr key={`${r.type}.${r.name}.${i}`} className="hover:bg-slate-50/70">
                            <td className="py-2.5 px-4 font-mono font-bold text-blue-600">
                              {r.type}
                            </td>
                            <td className="py-2.5 px-4 text-slate-800 font-semibold">{r.name}</td>
                            <td className="py-2.5 px-4 text-slate-500 font-mono">
                              {r.attributes
                                ? `${Object.keys(r.attributes).length} attributes`
                                : '0 attributes'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      <ThreatDetailPanel view={openThreat} onClose={() => setOpenThreat(null)} />
    </div>
  )
}
