import { useMemo, useState, useCallback } from 'react'
import { ReactFlow, Background, Controls, MiniMap, BackgroundVariant, ReactFlowProvider } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import ResourceNode from './ResourceNode'
import EmptyState from '../common/EmptyState'
import { layoutNodes } from '../../utils/graphLayout'
import { nodeRiskMap, SEVERITY_META } from '../../utils/risk'
import { Network } from 'lucide-react'
import { useTheme } from '../../context/ThemeContext'

const nodeTypes = { resource: ResourceNode }

export default function InfrastructureMap({ infraMap, findings = [], onSelectResource, height = 480 }) {
  const { isDark } = useTheme()
  const nodes = infraMap?.nodes || []
  const edges = infraMap?.edges || []
  const [selectedId, setSelectedId] = useState(null)

  const riskMap = useMemo(() => nodeRiskMap(findings), [findings])
  const { positions, validEdges } = useMemo(() => layoutNodes(nodes, edges), [nodes, edges])

  const neighborIds = useMemo(() => {
    if (!selectedId) return null
    const set = new Set([selectedId])
    validEdges.forEach(e => {
      if (e.source === selectedId) set.add(e.target)
      if (e.target === selectedId) set.add(e.source)
    })
    return set
  }, [selectedId, validEdges])

  const flowNodes = useMemo(() => nodes.map(n => ({
    id: n.id,
    type: 'resource',
    position: positions[n.id] || { x: 0, y: 0 },
    data: {
      resourceType: n.resource_type,
      name: n.name,
      risk: riskMap[n.id],
      dimmed: neighborIds ? !neighborIds.has(n.id) : false,
      raw: n,
    },
    selected: n.id === selectedId,
  })), [nodes, positions, riskMap, neighborIds, selectedId])

  const flowEdges = useMemo(() => validEdges.map((e, i) => {
    const active = neighborIds ? neighborIds.has(e.source) && neighborIds.has(e.target) : false
    return {
      id: `${e.source}->${e.target}-${i}`,
      source: e.source,
      target: e.target,
      label: e.relationship,
      animated: active,
      style: { stroke: active ? '#3b82f6' : isDark ? '#475569' : '#94a3b8', strokeWidth: active ? 2.2 : 1.3 },
      labelStyle: { fill: isDark ? '#94a3b8' : '#475569', fontSize: 10, fontWeight: 500 },
      labelBgStyle: {
        fill: isDark ? '#0f172a' : '#ffffff',
        fillOpacity: 0.95,
        stroke: isDark ? '#334155' : '#e2e8f0',
        strokeWidth: 1,
      },
    }
  }), [validEdges, neighborIds, isDark])

  const handleNodeClick = useCallback((_, node) => {
    setSelectedId(id => (id === node.id ? null : node.id))
    onSelectResource?.(node.data.raw, riskMap[node.id])
  }, [onSelectResource, riskMap])

  if (nodes.length === 0) {
    return (
      <div className="card">
        <EmptyState
          icon={Network}
          title="No infrastructure map available"
          description="Upload a Terraform configuration to visualize resources and their relationships."
          actionLabel="Start New Analysis"
          actionTo="/analyze?new=1"
        />
      </div>
    )
  }

  return (
    <div className="card p-0 overflow-hidden border-slate-200 dark:border-slate-800 shadow-sm bg-slate-50/50 dark:bg-slate-950/50">
      <div style={{ height }}>
        <ReactFlowProvider>
          <ReactFlow
            nodes={flowNodes}
            edges={flowEdges}
            nodeTypes={nodeTypes}
            onNodeClick={handleNodeClick}
            onPaneClick={() => { setSelectedId(null); onSelectResource?.(null) }}
            fitView
            fitViewOptions={{ padding: 0.25, minZoom: 0.5, maxZoom: 1.1 }}
            minZoom={0.3}
            maxZoom={1.5}
            proOptions={{ hideAttribution: true }}
            nodesDraggable
            nodesConnectable={false}
            elementsSelectable
          >
            <Background
              variant={BackgroundVariant.Dots}
              gap={20}
              size={1}
              color={isDark ? '#334155' : '#cbd5e1'}
            />
            <Controls showInteractive={false} />
            <MiniMap
              nodeColor={n => (n.data?.risk ? SEVERITY_META[n.data.risk.severity].color : isDark ? '#334155' : '#cbd5e1')}
              maskColor={isDark ? 'rgba(2,6,23,0.75)' : 'rgba(241,245,249,0.7)'}
              style={{
                background: isDark ? '#0f172a' : '#ffffff',
                border: isDark ? '1px solid #1e293b' : '1px solid #e2e8f0',
                borderRadius: 8,
              }}
              pannable
              zoomable
            />
          </ReactFlow>
        </ReactFlowProvider>
      </div>

      {/* Legend & Help bar */}
      <div className="flex items-center gap-4 flex-wrap px-4 py-3 border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-[11px] text-slate-600 dark:text-slate-400">
        <span className="font-bold text-slate-800 dark:text-slate-200">Risk Level:</span>
        {Object.entries(SEVERITY_META).filter(([k]) => k !== 'info').map(([k, m]) => (
          <span key={k} className="flex items-center gap-1.5 font-medium">
            <span className={`h-2 w-2 rounded-full ${m.dot}`} />
            {m.label}
          </span>
        ))}
        <span className="flex items-center gap-1.5 font-medium">
          <span className="h-2 w-2 rounded-full bg-slate-300 dark:bg-slate-700" />
          No findings
        </span>
        <span className="ml-auto text-slate-400 dark:text-slate-500 font-medium">Click node to inspect attributes & trace connections</span>
      </div>
    </div>
  )
}
