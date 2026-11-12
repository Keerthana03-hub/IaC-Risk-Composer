/**
 * SystemInfo.jsx
 * --------------
 * Dedicated technical & architectural overview page:
 * - Live Backend Health & Connectivity (GET /api/health)
 * - Security Scoring Methodology Formula & Weights
 * - STRIDE Threat Model-as-Code Engine Architecture
 * - Supported IaC Formats & 6-Step Analysis Pipeline
 */

import React, { useEffect, useState } from 'react'
import {
  Cpu,
  ShieldCheck,
  WifiOff,
  Loader2,
  Info,
  Layers,
  FileCode2,
  CheckCircle2,
  Activity,
  Server,
  Zap,
} from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import { getHealth } from '../api'
import { SEVERITY_META, SEVERITY_WEIGHTS, CONFIDENCE_FACTORS } from '../utils/risk'

export default function SystemInfo() {
  const [health, setHealth] = useState(null)
  const [status, setStatus] = useState('checking')
  const [latency, setLatency] = useState(null)

  function checkHealth() {
    setStatus('checking')
    const start = performance.now()
    getHealth()
      .then(d => {
        setLatency(Math.round(performance.now() - start))
        setHealth(d)
        setStatus('ok')
      })
      .catch(() => {
        setStatus('down')
        setLatency(null)
      })
  }

  useEffect(() => {
    checkHealth()
  }, [])

  return (
    <div className="space-y-6 max-w-5xl">
      <PageHeader
        title="System Architecture & Engine"
        description="Backend connectivity status, scoring methodology, STRIDE taxonomy, and threat engine pipeline."
      />

      {/* Backend Connectivity Status */}
      <div className="card space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="section-title flex items-center gap-2">
              <Server className="w-4 h-4 text-blue-600" />
              <span>Backend Connection & Service Health</span>
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Live status check pinging FastAPI backend at <code className="font-mono text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded">/api/health</code>
            </p>
          </div>
          <button
            onClick={checkHealth}
            className="btn-ghost text-xs border border-slate-200"
          >
            <Activity className="w-3.5 h-3.5 mr-1 text-slate-500" />
            <span>Recheck</span>
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 pt-2">
          {/* Status Box */}
          <div className="inset-box p-3.5">
            <p className="text-xs text-slate-500 mb-1">API Status</p>
            <div className="flex items-center gap-2">
              {status === 'checking' && <Loader2 className="w-4 h-4 text-slate-400 animate-spin" />}
              {status === 'ok' && <ShieldCheck className="w-4 h-4 text-emerald-600" />}
              {status === 'down' && <WifiOff className="w-4 h-4 text-rose-600" />}
              <span className={`text-sm font-semibold capitalize ${
                status === 'ok' ? 'text-emerald-700' : status === 'down' ? 'text-rose-700' : 'text-slate-600'
              }`}>
                {status === 'ok' ? 'Operational' : status === 'down' ? 'Disconnected' : 'Checking…'}
              </span>
            </div>
          </div>

          {/* Version Box */}
          <div className="inset-box p-3.5">
            <p className="text-xs text-slate-500 mb-1">Engine Version</p>
            <p className="text-sm font-semibold font-mono text-slate-800">
              v{health?.version || '1.0.0'}
            </p>
          </div>

          {/* Latency Box */}
          <div className="inset-box p-3.5">
            <p className="text-xs text-slate-500 mb-1">Roundtrip Latency</p>
            <p className="text-sm font-semibold font-mono text-slate-800">
              {latency !== null ? `${latency} ms` : '—'}
            </p>
          </div>

          {/* Database Engine Box */}
          <div className="inset-box p-3.5">
            <p className="text-xs text-slate-500 mb-1">Database Store</p>
            <p className="text-sm font-semibold text-slate-800">
              SQLite (WAL Enabled)
            </p>
          </div>
        </div>
      </div>

      {/* Transparent Security Score Methodology */}
      <div className="card space-y-5">
        <div>
          <h3 className="section-title flex items-center gap-2">
            <Info className="w-4 h-4 text-blue-600" />
            <span>Transparent Security Scoring Methodology</span>
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            The security score is deterministically derived from detected threats and risk confidence factors. No black-box estimations.
          </p>
        </div>

        {/* Formula Banner */}
        <div className="bg-slate-900 text-white rounded-xl p-4 font-mono text-xs sm:text-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-inner">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400 shrink-0" />
            <span className="text-emerald-400 font-bold">score</span>
            <span className="text-slate-400">=</span>
            <span className="text-white">100 − Σ (severity_weight × confidence_factor)</span>
          </div>
          <span className="text-[11px] text-slate-400 bg-slate-800 px-2.5 py-1 rounded">
            Clamped to range [0, 100]
          </span>
        </div>

        {/* Severity Deductions Breakdown */}
        <div>
          <h4 className="text-xs font-semibold text-slate-700 uppercase tracking-wider mb-2.5">
            Base Severity Deduction Weights
          </h4>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {Object.entries(SEVERITY_WEIGHTS).map(([sev, weight]) => {
              const meta = SEVERITY_META[sev] || { label: sev, badge: 'badge-low', text: 'text-slate-600' }
              return (
                <div key={sev} className="inset-box p-3 flex items-center justify-between">
                  <span className={`badge ${meta.badge} font-semibold text-xs`}>{meta.label}</span>
                  <span className="text-xs font-mono font-bold text-slate-800">−{weight} pts</span>
                </div>
              )
            })}
          </div>
        </div>

        {/* Confidence Multipliers */}
        <div>
          <h4 className="text-xs font-semibold text-slate-700 uppercase tracking-wider mb-2.5">
            Detection Confidence Scaling Factors
          </h4>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div className="inset-box p-3">
              <div className="flex items-center justify-between font-semibold text-slate-800 mb-1">
                <span>High Confidence</span>
                <span className="font-mono text-blue-600">× {CONFIDENCE_FACTORS.high} (100%)</span>
              </div>
              <p className="text-[11px] text-slate-500">Explicit misconfigurations directly declared in IaC code blocks.</p>
            </div>
            <div className="inset-box p-3">
              <div className="flex items-center justify-between font-semibold text-slate-800 mb-1">
                <span>Medium Confidence</span>
                <span className="font-mono text-blue-600">× {CONFIDENCE_FACTORS.medium} (75%)</span>
              </div>
              <p className="text-[11px] text-slate-500">Missing secure defaults or unencrypted transport configurations.</p>
            </div>
            <div className="inset-box p-3">
              <div className="flex items-center justify-between font-semibold text-slate-800 mb-1">
                <span>Low Confidence</span>
                <span className="font-mono text-blue-600">× {CONFIDENCE_FACTORS.low} (50%)</span>
              </div>
              <p className="text-[11px] text-slate-500">Heuristic warnings or contextual threat hypotheses requiring manual audit.</p>
            </div>
          </div>
        </div>
      </div>

      {/* 6-Step Pipeline Architecture */}
      <div className="card space-y-5">
        <div>
          <h3 className="section-title flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-600" />
            <span>Analysis Engine 6-Step Pipeline</span>
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Every IaC submission runs synchronously through an automated six-stage security evaluation engine.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
          <div className="border border-slate-200 dark:border-slate-800 rounded-xl p-3.5 bg-slate-50/50 dark:bg-slate-900/60 space-y-1.5">
            <div className="flex items-center gap-2 text-blue-600 dark:text-blue-400 font-semibold text-xs">
              <span className="w-5 h-5 rounded-full bg-blue-100 dark:bg-blue-950 flex items-center justify-center text-[11px]">1</span>
              <span>IaC Parsing & AST</span>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              Extracts resources, provider declarations, and attribute maps from Terraform HCL, CloudFormation, or Kubernetes manifests.
            </p>
          </div>

          <div className="border border-slate-200 dark:border-slate-800 rounded-xl p-3.5 bg-slate-50/50 dark:bg-slate-900/60 space-y-1.5">
            <div className="flex items-center gap-2 text-blue-600 dark:text-blue-400 font-semibold text-xs">
              <span className="w-5 h-5 rounded-full bg-blue-100 dark:bg-blue-950 flex items-center justify-center text-[11px]">2</span>
              <span>Infrastructure Mapping</span>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              Constructs an architecture topology map resolving references, ingress/egress relationships, and security boundary zones.
            </p>
          </div>

          <div className="border border-slate-200 dark:border-slate-800 rounded-xl p-3.5 bg-slate-50/50 dark:bg-slate-900/60 space-y-1.5">
            <div className="flex items-center gap-2 text-blue-600 dark:text-blue-400 font-semibold text-xs">
              <span className="w-5 h-5 rounded-full bg-blue-100 dark:bg-blue-950 flex items-center justify-center text-[11px]">3</span>
              <span>STRIDE Threat Detection</span>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              Executes deterministic pattern matchers inspecting open ports, permissive IAM roles, unencrypted buckets, and network perimeters.
            </p>
          </div>

          <div className="border border-slate-200 dark:border-slate-800 rounded-xl p-3.5 bg-slate-50/50 dark:bg-slate-900/60 space-y-1.5">
            <div className="flex items-center gap-2 text-blue-600 dark:text-blue-400 font-semibold text-xs">
              <span className="w-5 h-5 rounded-full bg-blue-100 dark:bg-blue-950 flex items-center justify-center text-[11px]">4</span>
              <span>Multi-Factor Risk Scoring</span>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              Weights findings by severity and confidence levels, computing per-resource and overall workspace security posture grades.
            </p>
          </div>

          <div className="border border-slate-200 dark:border-slate-800 rounded-xl p-3.5 bg-slate-50/50 dark:bg-slate-900/60 space-y-1.5">
            <div className="flex items-center gap-2 text-blue-600 dark:text-blue-400 font-semibold text-xs">
              <span className="w-5 h-5 rounded-full bg-blue-100 dark:bg-blue-950 flex items-center justify-center text-[11px]">5</span>
              <span>Plain-Language Synthesis</span>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              Generates executive explanations detailing why each misconfiguration matters and what threat actor vectors it enables.
            </p>
          </div>

          <div className="border border-slate-200 dark:border-slate-800 rounded-xl p-3.5 bg-slate-50/50 dark:bg-slate-900/60 space-y-1.5">
            <div className="flex items-center gap-2 text-blue-600 dark:text-blue-400 font-semibold text-xs">
              <span className="w-5 h-5 rounded-full bg-blue-100 dark:bg-blue-950 flex items-center justify-center text-[11px]">6</span>
              <span>Safe Code Patch Generation</span>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              Synthesizes ready-to-apply HCL/YAML remediation snippets to resolve risks while preserving intended infrastructure behavior.
            </p>
          </div>
        </div>
      </div>

      {/* STRIDE Taxonomy Reference */}
      <div className="card space-y-4">
        <div>
          <h3 className="section-title flex items-center gap-2">
            <FileCode2 className="w-4 h-4 text-blue-600" />
            <span>STRIDE Threat Classification Reference</span>
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Categorization model applied across all rule evaluators.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 text-xs">
          <div className="inset-box p-3 space-y-1">
            <span className="font-bold text-slate-900">S — Spoofing</span>
            <p className="text-slate-500">Violating authenticity; pretending to be a legitimate server, container, or service.</p>
          </div>
          <div className="inset-box p-3 space-y-1">
            <span className="font-bold text-slate-900">T — Tampering</span>
            <p className="text-slate-500">Modifying configuration data, state files, or traffic without authorization.</p>
          </div>
          <div className="inset-box p-3 space-y-1">
            <span className="font-bold text-slate-900">R — Repudiation</span>
            <p className="text-slate-500">Lack of audit logging, VPC flow logs, or CloudTrail events to prove malicious actions.</p>
          </div>
          <div className="inset-box p-3 space-y-1">
            <span className="font-bold text-slate-900">I — Information Disclosure</span>
            <p className="text-slate-500">Exposing sensitive databases, API keys, unencrypted storage, or public buckets.</p>
          </div>
          <div className="inset-box p-3 space-y-1">
            <span className="font-bold text-slate-900">D — Denial of Service</span>
            <p className="text-slate-500">Missing rate limits, unthrottled endpoints, or single points of failure in compute.</p>
          </div>
          <div className="inset-box p-3 space-y-1">
            <span className="font-bold text-slate-900">E — Elevation of Privilege</span>
            <p className="text-slate-500">Over-permissive IAM roles (`*` actions on `*` resources) or root container execution.</p>
          </div>
        </div>
      </div>
    </div>
  )
}
