import SidePanel from '../common/SidePanel'
import SeverityBadge from '../common/SeverityBadge'
import { Box, Layers, ShieldCheck } from 'lucide-react'

export default function ResourceDetails({ resource, risk, findings = [], onClose }) {
  if (!resource) return null
  const related = findings.filter(f => f.affected_resource_id === resource.id)

  return (
    <SidePanel
      open={!!resource}
      onClose={onClose}
      title={resource.name}
      subtitle={resource.id}
      badge={
        <span className="inline-flex items-center gap-1.5 text-[11px] font-mono text-blue-700 bg-blue-50 border border-blue-200 px-2 py-0.5 rounded-full font-bold">
          <Box className="h-3 w-3" /> {resource.resource_type}
        </span>
      }
    >
      {risk ? (
        <div className="inset-box p-3.5 mb-5 flex items-center justify-between bg-slate-50 border-slate-200">
          <span className="text-xs font-semibold text-slate-700">Highest Threat Severity</span>
          <SeverityBadge severity={risk.severity} size="lg" />
        </div>
      ) : (
        <div className="inset-box p-3.5 mb-5 text-xs text-emerald-700 bg-emerald-50 border-emerald-200 font-semibold flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-emerald-600" /> No security findings for this resource.
        </div>
      )}

      {resource.attributes && Object.keys(resource.attributes).length > 0 && (
        <div className="mb-5">
          <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2">
            Resource Attributes
          </h4>
          <div className="inset-box divide-y divide-slate-100 bg-slate-50/50 text-xs border-slate-200">
            {Object.entries(resource.attributes).map(([k, v]) => (
              <div key={k} className="flex gap-3 px-3.5 py-2.5">
                <span className="text-slate-500 font-medium flex-shrink-0 text-[11px]">{k}</span>
                <span className="text-slate-900 font-mono text-[11px] truncate">
                  {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {related.length > 0 && (
        <div>
          <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2">
            Findings on this Resource ({related.length})
          </h4>
          <div className="space-y-2.5">
            {related.map(f => (
              <div key={f.finding_id} className="inset-box p-3.5 bg-white border-slate-200 shadow-2xs">
                <div className="flex items-center gap-2 mb-1.5">
                  <SeverityBadge severity={f.severity} />
                  <span className="font-mono text-[11px] text-slate-400">{f.finding_id}</span>
                </div>
                <p className="text-xs font-bold text-slate-900 leading-snug">{f.title}</p>
                {f.description && (
                  <p className="text-[11px] text-slate-500 mt-1 line-clamp-2 leading-relaxed">
                    {f.description}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </SidePanel>
  )
}
