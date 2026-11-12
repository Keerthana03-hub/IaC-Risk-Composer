export function Skeleton({ className = '' }) {
  return <div className={`skeleton ${className}`} />
}

export function StatCardSkeleton() {
  return (
    <div className="card space-y-3">
      <Skeleton className="h-4 w-24" />
      <Skeleton className="h-8 w-16" />
      <Skeleton className="h-3 w-32" />
    </div>
  )
}

export function CardSkeleton({ lines = 3 }) {
  return (
    <div className="card space-y-3">
      <Skeleton className="h-4 w-1/3" />
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} className="h-3 w-full" />
      ))}
    </div>
  )
}

export function ChartSkeleton() {
  return (
    <div className="card">
      <Skeleton className="h-4 w-40 mb-4" />
      <Skeleton className="h-56 w-full" />
    </div>
  )
}
