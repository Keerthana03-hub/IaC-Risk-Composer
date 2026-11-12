/**
 * risk.js – severity helpers and data-derivation utilities.
 *
 * Everything here is computed from the real /api/analyze (or /api/reports/{id})
 * response. Nothing is hard-coded or invented; when data is absent we return
 * null / empty structures so the UI can render an honest empty state.
 */

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

// Full class strings (not template fragments) so Tailwind can see them.
export const SEVERITY_META = {
  critical: { label: 'Critical', color: '#e11d48', badge: 'bg-rose-50 text-rose-700 border-rose-200',
              dot: 'bg-rose-600', text: 'text-rose-600', border: 'border-rose-300', soft: 'bg-rose-50', ring: 'ring-rose-500/30' },
  high:     { label: 'High', color: '#ea580c', badge: 'bg-orange-50 text-orange-700 border-orange-200',
              dot: 'bg-orange-500', text: 'text-orange-600', border: 'border-orange-300', soft: 'bg-orange-50', ring: 'ring-orange-500/30' },
  medium:   { label: 'Medium', color: '#d97706', badge: 'bg-amber-50 text-amber-800 border-amber-200',
              dot: 'bg-amber-500', text: 'text-amber-600', border: 'border-amber-300', soft: 'bg-amber-50', ring: 'ring-amber-500/30' },
  low:      { label: 'Low', color: '#16a34a', badge: 'bg-emerald-50 text-emerald-700 border-emerald-200',
              dot: 'bg-emerald-500', text: 'text-emerald-600', border: 'border-emerald-300', soft: 'bg-emerald-50', ring: 'ring-emerald-500/30' },
  info:     { label: 'Info', color: '#64748b', badge: 'bg-slate-100 text-slate-700 border-slate-200',
              dot: 'bg-slate-400', text: 'text-slate-600', border: 'border-slate-300', soft: 'bg-slate-100', ring: 'ring-slate-400/30' },
}

// Used only for the derived posture score (see computeSecurityScore).
export const SEVERITY_WEIGHTS = { critical: 25, high: 15, medium: 8, low: 3, info: 1 }
// Same confidence factors the backend risk engine uses.
export const CONFIDENCE_FACTORS = { high: 1, medium: 0.75, low: 0.5 }

export function normalizeSeverity(value) {
  const s = String(value ?? '').trim().toLowerCase()
  if (SEVERITY_META[s]) return s
  return 'info' // negligible / informational / unknown
}

/** True for the backend's real severity/risk-level words (not "Not Assessed" / "Assessed" placeholders). */
export function isRealSeverity(value) {
  return SEVERITY_ORDER.slice(0, 4).includes(String(value ?? '').trim().toLowerCase())
}

export function severityRank(value) {
  return SEVERITY_ORDER.indexOf(normalizeSeverity(value)) // 0 = most severe
}

export function countBySeverity(findings = []) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 }
  for (const f of findings) {
    counts[normalizeSeverity(f?.severity)] += 1
    counts.total += 1
  }
  return counts
}

/** Most severe level present in the findings, or null when there are none. */
export function highestSeverity(findings = []) {
  let best = null
  for (const f of findings) {
    const s = normalizeSeverity(f?.severity)
    if (best === null || SEVERITY_ORDER.indexOf(s) < SEVERITY_ORDER.indexOf(best)) best = s
  }
  return best
}

/**
 * Derived security posture score (0–100, higher = better).
 *
 * The backend does not return a posture score, so this is a transparent,
 * frontend-derived heuristic:
 *
 *   score = 100 − Σ ( severity weight × confidence factor )   (clamped 0–100)
 *
 * Weights: Critical 25, High 15, Medium 8, Low 3, Info 1.
 * Confidence factor: High 1.0, Medium 0.75, Low 0.5 (same as the risk engine).
 *
 * Returns null when there is nothing to score (no analysis / no resources).
 */
export function computeSecurityScore(result) {
  if (!result || !Array.isArray(result.threat_findings)) return null
  const findings = result.threat_findings
  if (!(result.resource_count > 0) && findings.length === 0) return null

  const breakdown = Object.fromEntries(SEVERITY_ORDER.map(s => [s, { count: 0, penalty: 0 }]))
  let penalty = 0
  for (const f of findings) {
    const sev = normalizeSeverity(f.severity)
    const cf = CONFIDENCE_FACTORS[String(f.confidence ?? '').toLowerCase()] ?? 1
    const p = SEVERITY_WEIGHTS[sev] * cf
    breakdown[sev].count += 1
    breakdown[sev].penalty += p
    penalty += p
  }
  const score = Math.max(0, Math.min(100, Math.round(100 - penalty)))
  return { score, penalty: Math.round(penalty * 100) / 100, breakdown, ...scoreBand(score) }
}

export function scoreBand(score) {
  if (score >= 85) return { band: 'low', label: 'Low Risk' }
  if (score >= 65) return { band: 'medium', label: 'Moderate Risk' }
  if (score >= 40) return { band: 'high', label: 'High Risk' }
  return { band: 'critical', label: 'Critical Risk' }
}

/** [{ type, count }] – counted from the real resources list, most common first. */
export function resourceTypeCounts(result) {
  const resources = Array.isArray(result?.resources) ? result.resources : []
  const map = new Map()
  for (const r of resources) map.set(r.type, (map.get(r.type) || 0) + 1)
  if (map.size === 0 && Array.isArray(result?.infrastructure_map?.nodes)) {
    for (const n of result.infrastructure_map.nodes) map.set(n.resource_type, (map.get(n.resource_type) || 0) + 1)
  }
  return [...map.entries()].map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count)
}

/** Findings grouped per affected resource, with a per-severity breakdown. */
export function groupThreatsByResource(findings = []) {
  const map = new Map()
  for (const f of findings) {
    const id = f.affected_resource_id || `${f.affected_resource_type}.${f.affected_resource_name}`
    if (!map.has(id)) {
      map.set(id, { id, name: f.affected_resource_name || id, type: f.affected_resource_type,
                    critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 })
    }
    const row = map.get(id)
    row[normalizeSeverity(f.severity)] += 1
    row.total += 1
  }
  return [...map.values()].sort((a, b) => b.total - a.total)
}

/** id → { severity (highest) | null, count } for every resource that has findings. */
export function nodeRiskMap(findings = []) {
  const map = {}
  for (const f of findings) {
    const id = f.affected_resource_id
    if (!id) continue
    const sev = normalizeSeverity(f.severity)
    if (!map[id]) map[id] = { severity: sev, count: 0 }
    map[id].count += 1
    if (SEVERITY_ORDER.indexOf(sev) < SEVERITY_ORDER.indexOf(map[id].severity)) map[id].severity = sev
  }
  return map
}
