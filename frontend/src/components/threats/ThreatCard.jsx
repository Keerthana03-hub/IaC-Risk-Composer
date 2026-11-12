import { ChevronRight, Box } from 'lucide-react'
import SeverityBadge from '../common/SeverityBadge'
import { SEVERITY_META } from '../../utils/risk'

export default function ThreatCard({ view, onOpen, style }) {
  const meta = SEVERITY_META[view.severity]
  return (
    <button
      onClick={() => onOpen(view)}
      style={style}
      className={`w-full text-left card card-hover animate-slide-up border-l-4 ${meta.border} group p-5 bg-white dark:bg-slate-900 shadow-2xs hover:shadow-md transition-all`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <SeverityBadge severity={view.severity} />
            {view.finding.detection_status && (
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                {view.finding.detection_status}
              </span>
            )}
          </div>
          <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 leading-snug group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
            {view.title}
          </h3>
          <p className="flex items-center gap-1.5 text-xs text-blue-600 dark:text-blue-400 font-mono mt-1 truncate font-medium">
            <Box className="h-3.5 w-3.5 flex-shrink-0" /> {view.resourceId}
          </p>
        </div>
        <ChevronRight className="h-4 w-4 text-slate-400 group-hover:text-blue-600 dark:group-hover:text-blue-400 group-hover:translate-x-0.5 transition-all flex-shrink-0 mt-1" />
      </div>

      {view.description && (
        <p className="text-xs text-slate-600 dark:text-slate-300 mt-2.5 line-clamp-2 leading-relaxed">
          {view.description}
        </p>
      )}

      {view.controls.length > 0 && (
        <div className="mt-3.5 pt-3 border-t border-slate-100 dark:border-slate-800">
          <p className="text-[10px] uppercase font-bold tracking-wider text-slate-400 dark:text-slate-500 mb-1.5">
            Recommended Action
          </p>
          <ul className="space-y-1">
            {view.controls.slice(0, 2).map((c, i) => (
              <li key={i} className="text-xs text-slate-700 dark:text-slate-300 flex gap-2 font-medium">
                <span className="text-emerald-600 dark:text-emerald-400 font-bold flex-shrink-0">&bull;</span>
                <span className="line-clamp-1">{c}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </button>
  )
}
