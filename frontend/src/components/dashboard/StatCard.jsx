import AnimatedNumber from '../common/AnimatedNumber'
import { Skeleton } from '../common/Skeleton'

export default function StatCard({ icon: Icon, label, value, sub, tone = 'default', loading }) {
  const toneCls = {
    default: 'text-slate-900 dark:text-slate-100',
    cyber: 'text-blue-600 dark:text-blue-400',
    critical: 'text-rose-600 dark:text-rose-400',
    high: 'text-orange-600 dark:text-orange-400',
    good: 'text-emerald-600 dark:text-emerald-400',
  }[tone]

  return (
    <div className="card card-hover flex flex-col justify-between p-4 sm:p-5">
      <div className="flex items-center justify-between mb-2">
        <span className="eyebrow">{label}</span>
        {Icon && (
          <div className="h-8 w-8 rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-100 dark:border-slate-700 flex items-center justify-center">
            <Icon className="h-4 w-4 text-slate-500 dark:text-slate-400" />
          </div>
        )}
      </div>
      {loading ? (
        <Skeleton className="h-8 w-16" />
      ) : (
        <div className="my-1">
          <span className={`text-2xl sm:text-3xl font-extrabold tracking-tight tabular-nums ${toneCls}`}>
            {typeof value === 'number' ? <AnimatedNumber value={value} /> : value}
          </span>
        </div>
      )}
      {sub && <span className="text-[11px] text-slate-500 dark:text-slate-400 truncate">{sub}</span>}
    </div>
  )
}
