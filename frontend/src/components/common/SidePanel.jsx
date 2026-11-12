import { useEffect } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'

/** Right-edge slide-in panel for Threat / Resource detail views in light & dark theme. */
export default function SidePanel({ open, onClose, title, subtitle, badge, children }) {
  useEffect(() => {
    if (!open) return
    function onKey(e) { if (e.key === 'Escape') onClose?.() }
    document.addEventListener('keydown', onKey)
    document.body.style.overflow = 'hidden'
    return () => { document.removeEventListener('keydown', onKey); document.body.style.overflow = '' }
  }, [open, onClose])

  if (!open) return null

  return createPortal(
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm animate-fade-in" onClick={onClose} />
      <div className="relative h-full w-full sm:w-[500px] bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-800 shadow-2xl flex flex-col animate-slide-in-right">
        <div className="flex items-start justify-between gap-4 px-6 py-4 border-b border-slate-100 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/60 flex-shrink-0">
          <div className="min-w-0">
            {badge}
            <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 mt-1.5 leading-snug">{title}</h3>
            {subtitle && <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono truncate">{subtitle}</p>}
          </div>
          <button onClick={onClose} className="icon-btn hover:bg-slate-200/60 dark:hover:bg-slate-800 flex-shrink-0" aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-6 py-5">{children}</div>
      </div>
    </div>,
    document.body,
  )
}
