/**
 * Infrastructure.jsx
 * -------------------
 * Infrastructure Map & Explorer (Section 9).
 * Answers: "What infrastructure does this project contain, and where are the risks?"
 * Interactive architecture explorer powered by React Flow with resource inspection side panel.
 */

import React, { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Network, Plus, Search, Filter, Layers, FolderGit2 } from 'lucide-react'

import { useAnalysis } from '../context/AnalysisContext'
import PageHeader from '../components/common/PageHeader'
import ErrorBanner from '../components/common/ErrorBanner'
import EmptyState from '../components/common/EmptyState'
import { ChartSkeleton } from '../components/common/Skeleton'
import InfrastructureMap from '../components/infrastructure/InfrastructureMap'
import ResourceDetails from '../components/infrastructure/ResourceDetails'
import { nodeRiskMap } from '../utils/risk'
import { formatDateTime } from '../utils/format'

export default function Infrastructure() {
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

  const [selected, setSelected] = useState(null)
  const [resourceFilter, setResourceFilter] = useState('all')

  const findings = result?.threat_findings || []
  const rawInfraMap = result?.infrastructure_map || { nodes: [], edges: [] }

  // Extract unique resource types for filter dropdown
  const resourceTypes = useMemo(() => {
    const set = new Set()
    for (const node of rawInfraMap.nodes || []) {
      if (node.resource_type) set.add(node.resource_type)
    }
    return Array.from(set).sort()
  }, [rawInfraMap.nodes])

  // Filter nodes if user selects a specific resource type
  const filteredInfraMap = useMemo(() => {
    if (resourceFilter === 'all') return rawInfraMap
    const matchingNodes = (rawInfraMap.nodes || []).filter(
      n => n.resource_type === resourceFilter
    )
    const matchingIds = new Set(matchingNodes.map(n => n.id))
    const matchingEdges = (rawInfraMap.edges || []).filter(
      e => matchingIds.has(e.source) || matchingIds.has(e.target)
    )
    return { nodes: matchingNodes, edges: matchingEdges }
  }, [rawInfraMap, resourceFilter])

  return (
    <div className="space-y-6">
      <PageHeader
        title="Infrastructure Map"
        description="Interactive architecture explorer: discover resources, dependencies, and identified security risks."
        actions={
          <div className="flex items-center gap-2 flex-wrap">
            {/* Workspace Project Dropdown */}
            {projects.length > 0 && (
              <select
                value={currentProjectId || ''}
                onChange={e => selectProject(e.target.value)}
                className="input w-auto text-xs font-semibold py-2 px-3 max-w-[200px]"
                title="Select Project Workspace"
              >
                {projects.map(p => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            )}

            {/* Analysis Scan Dropdown */}
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

      {loading ? (
        <ChartSkeleton />
      ) : !result ? (
        <div className="card">
          <EmptyState
            icon={Network}
            title="No infrastructure architecture available"
            description="Upload an infrastructure configuration file to generate an interactive topology graph."
            actionLabel="Start New Analysis"
            actionTo="/analyze?new=1"
          />
        </div>
      ) : (
        <>
          {/* Metadata bar */}
          <div className="flex items-center justify-between flex-wrap gap-3 bg-white p-3.5 rounded-xl border border-slate-200 text-xs shadow-2xs">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono font-bold text-blue-600 bg-blue-50 px-2 py-0.5 rounded border border-blue-200">
                {result.filename}
              </span>
              <span className="text-slate-400">&middot;</span>
              <span className="font-semibold text-slate-700">
                {filteredInfraMap.nodes?.length || 0} resources mapped
              </span>
              <span className="text-slate-400">&middot;</span>
              <span className="text-slate-600">
                {filteredInfraMap.edges?.length || 0} relationships
              </span>
              {result.project_name && (
                <>
                  <span className="text-slate-400">&middot;</span>
                  <span className="text-slate-500 font-medium">
                    Workspace: {result.project_name}
                  </span>
                </>
              )}
            </div>

            <div className="flex items-center gap-3">
              {resourceTypes.length > 0 && (
                <div className="flex items-center gap-1.5">
                  <Filter className="h-3.5 w-3.5 text-slate-400" />
                  <select
                    value={resourceFilter}
                    onChange={e => setResourceFilter(e.target.value)}
                    className="input w-auto text-xs py-1 px-2.5"
                  >
                    <option value="all">All Resource Types ({resourceTypes.length})</option>
                    {resourceTypes.map(t => (
                      <option key={t} value={t}>
                        {t}
                      </option>
                    ))}
                  </select>
                </div>
              )}

              <Link
                to="/analyze?new=1"
                className="btn-ghost text-xs py-1 px-2.5 font-semibold text-blue-600"
              >
                <Plus className="h-3.5 w-3.5" /> New Analysis
              </Link>
            </div>
          </div>

          {/* Interactive Topology Graph */}
          <InfrastructureMap
            infraMap={filteredInfraMap}
            findings={findings}
            height={580}
            onSelectResource={(resource, risk) =>
              setSelected(resource ? { resource, risk } : null)
            }
          />
        </>
      )}

      {/* Slide-out details drawer */}
      <ResourceDetails
        resource={selected?.resource}
        risk={selected?.risk}
        findings={findings}
        onClose={() => setSelected(null)}
      />
    </div>
  )
}
