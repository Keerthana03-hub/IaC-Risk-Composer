export default function PageHeader({ title, description, actions }) {
  return (
    <div className="flex items-start justify-between flex-wrap gap-4 pb-1">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100 tracking-tight">{title}</h1>
        {description && <p className="text-slate-500 dark:text-slate-400 text-xs sm:text-sm mt-1 max-w-2xl">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2.5 flex-wrap">{actions}</div>}
    </div>
  )
}
