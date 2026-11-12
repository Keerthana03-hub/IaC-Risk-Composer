import { Link } from 'react-router-dom'
import { Inbox } from 'lucide-react'

export default function EmptyState({ icon: Icon = Inbox, title, description, actionLabel, actionTo, onAction }) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-14 px-6 animate-fade-in">
      <div className="h-14 w-14 rounded-2xl bg-blue-50 dark:bg-blue-950/60 border border-blue-100 dark:border-blue-900/60 flex items-center justify-center mb-4 shadow-xs">
        <Icon className="h-6 w-6 text-blue-600 dark:text-blue-400" />
      </div>
      <h3 className="text-slate-900 dark:text-slate-100 font-bold text-base">{title}</h3>
      {description && <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 mt-1.5 max-w-sm leading-relaxed">{description}</p>}
      {actionLabel && (actionTo ? (
        <Link to={actionTo} className="btn-primary text-xs font-semibold py-2 px-4 shadow-sm mt-5">{actionLabel}</Link>
      ) : (
        <button onClick={onAction} className="btn-primary text-xs font-semibold py-2 px-4 shadow-sm mt-5">{actionLabel}</button>
      ))}
    </div>
  )
}
