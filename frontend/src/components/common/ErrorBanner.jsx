import { AlertTriangle, RotateCcw } from 'lucide-react'

export default function ErrorBanner({ title = 'Something went wrong', message, onRetry }) {
  return (
    <div className="flex items-start gap-3 bg-rose-50 border border-rose-200 rounded-xl px-4 py-3 text-rose-800 animate-fade-in shadow-xs">
      <AlertTriangle className="h-4 w-4 text-rose-600 mt-0.5 flex-shrink-0" />
      <div className="flex-1 min-w-0">
        <p className="text-xs sm:text-sm font-semibold text-rose-900">{title}</p>
        {message && <p className="text-xs text-rose-700 mt-0.5">{message}</p>}
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="flex items-center gap-1.5 text-xs font-semibold text-rose-700 hover:text-rose-900 transition-colors flex-shrink-0"
        >
          <RotateCcw className="h-3.5 w-3.5" /> Retry
        </button>
      )}
    </div>
  )
}
