/**
 * The backend stores timestamps in SQLite as naive UTC datetimes, so the ISO
 * string it returns has no timezone suffix. `new Date('2026-01-01T10:00:00')`
 * would be interpreted as *local* time, shifting every date. Treat timezone-less
 * strings as UTC.
 */
export function parseApiDate(iso) {
  if (!iso) return null
  const s = String(iso)
  const hasTz = /([zZ]|[+-]\d{2}:?\d{2})$/.test(s)
  const d = new Date(hasTz ? s : `${s}Z`)
  return Number.isNaN(d.getTime()) ? null : d
}

export function formatDateTime(iso) {
  const d = parseApiDate(iso)
  if (!d) return '—'
  return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

export function formatDate(iso) {
  const d = parseApiDate(iso)
  if (!d) return '—'
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' })
}

export function formatTime(iso) {
  const d = parseApiDate(iso)
  if (!d) return ''
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

/** "Today" / "Yesterday" / "Mon, Sep 12, 2026" – used to group the history timeline. */
export function dayLabel(iso, now = new Date()) {
  const d = parseApiDate(iso)
  if (!d) return 'Unknown date'
  const startOf = x => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime()
  const diffDays = Math.round((startOf(now) - startOf(d)) / 86400000)
  if (diffDays === 0) return 'Today'
  if (diffDays === 1) return 'Yesterday'
  return d.toLocaleDateString(undefined, { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' })
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

export function pluralize(n, one, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`
}

export function timeAgo(iso) {
  const d = parseApiDate(iso)
  if (!d) return '—'
  const seconds = Math.floor((Date.now() - d.getTime()) / 1000)
  if (seconds < 45) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days === 1) return 'yesterday'
  if (days < 30) return `${days}d ago`
  const months = Math.floor(days / 30)
  if (months < 12) return `${months}mo ago`
  return `${Math.floor(months / 12)}y ago`
}

