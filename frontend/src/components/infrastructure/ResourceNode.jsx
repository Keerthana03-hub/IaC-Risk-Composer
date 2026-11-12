import { Handle, Position } from '@xyflow/react'
import { Server, Database, Network, ShieldQuestion, Box } from 'lucide-react'
import { SEVERITY_META } from '../../utils/risk'

const TYPE_ICON = [
  [/instance|ec2|compute|vm/i, Server],
  [/bucket|storage|db|rds|database/i, Database],
  [/security_group|firewall|acl|network|vpc|subnet/i, Network],
]

function iconFor(type) {
  return (TYPE_ICON.find(([re]) => re.test(type))?.[1]) || Box
}

/** Custom React Flow node styled for light & dark theme. */
export default function ResourceNode({ data, selected }) {
  const Icon = iconFor(data.resourceType)
  const risk = data.risk // { severity, count } | undefined
  const meta = risk ? SEVERITY_META[risk.severity] : null

  return (
    <div
      className={`w-[240px] rounded-xl border bg-white dark:bg-slate-900 px-3.5 py-3 shadow-sm transition-all duration-150
        ${
          selected
            ? 'border-blue-600 ring-2 ring-blue-500/30 -translate-y-0.5 shadow-md'
            : meta
            ? meta.border
            : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
        }
        ${data.dimmed ? 'opacity-30' : 'opacity-100'}`}
    >
      <Handle type="target" position={Position.Top} className="!bg-slate-400 !border-white dark:!border-slate-900" />
      <div className="flex items-start gap-2.5">
        <div
          className={`h-8 w-8 rounded-lg flex items-center justify-center flex-shrink-0 ${
            meta ? meta.soft : 'bg-slate-100 dark:bg-slate-800'
          }`}
        >
          <Icon className={`h-4 w-4 ${meta ? meta.text : 'text-slate-600 dark:text-slate-300'}`} />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-[10px] font-mono text-slate-400 dark:text-slate-500 uppercase font-semibold truncate">
            {data.resourceType}
          </p>
          <p className="text-xs font-bold text-slate-900 dark:text-slate-100 truncate">{data.name}</p>
        </div>
        {risk && (
          <span className={`flex-shrink-0 text-[10px] font-extrabold px-1.5 py-0.5 rounded-full ${meta.badge}`}>
            {risk.count}
          </span>
        )}
      </div>

      {risk ? (
        <p className={`text-[11px] mt-2 font-bold ${meta.text}`}>
          {meta.label} risk &middot; {risk.count} finding{risk.count !== 1 ? 's' : ''}
        </p>
      ) : (
        <p className="text-[11px] mt-2 font-medium text-emerald-600 dark:text-emerald-400">No findings &middot; Secure</p>
      )}

      <Handle type="source" position={Position.Bottom} className="!bg-slate-400 !border-white dark:!border-slate-900" />
    </div>
  )
}

export function UnknownRiskIcon() {
  return <ShieldQuestion className="h-4 w-4" />
}
