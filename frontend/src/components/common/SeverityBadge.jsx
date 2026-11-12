import { SEVERITY_META, normalizeSeverity } from '../../utils/risk'

export default function SeverityBadge({ severity, size = 'sm' }) {
  const sev = normalizeSeverity(severity)
  const meta = SEVERITY_META[sev]
  const sizeCls = size === 'lg' ? 'text-xs px-2.5 py-1' : 'text-[11px] px-2 py-0.5'
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border font-bold uppercase tracking-wide ${meta.badge} ${sizeCls}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
      {meta.label}
    </span>
  )
}
