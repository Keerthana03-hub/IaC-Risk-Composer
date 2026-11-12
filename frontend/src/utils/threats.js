import { normalizeSeverity, severityRank } from './risk'

/**
 * Join threat_findings with their risk_explanations and remediations
 * (all keyed by finding_id) into one view-model per threat.
 * Only real backend fields are used; missing pieces stay null / empty.
 */
export function buildThreatViews(result) {
  const findings = Array.isArray(result?.threat_findings) ? result.threat_findings : []
  const explanations = Object.fromEntries((result?.risk_explanations ?? []).map(e => [e.finding_id, e]))
  const remediationsByFinding = {}
  for (const r of result?.remediations ?? []) (remediationsByFinding[r.finding_id] ||= []).push(r)

  const views = findings.map((f, idx) => {
    const explanation = explanations[f.finding_id] ?? null
    const remediations = remediationsByFinding[f.finding_id] ?? []

    const controls = firstNonEmpty(
      explanation?.recommended_actions,
      remediations.flatMap(r => r.recommended_actions ?? []),
      f.recommendation ? [f.recommendation] : [],
    )

    return {
      id: f.finding_id || `finding-${idx}`,
      finding: f,
      severity: normalizeSeverity(f.severity),
      title: f.title,
      resourceId: f.affected_resource_id || `${f.affected_resource_type}.${f.affected_resource_name}`,
      resourceType: f.affected_resource_type,
      resourceName: f.affected_resource_name,
      description: f.description,
      impact: f.impact || null,
      attackScenario: f.attack_scenario || explanation?.attack_scenario || null, // not produced by the current backend
      controls,
      explanation,
      remediations,
    }
  })

  return views.sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
}

function firstNonEmpty(...lists) {
  return lists.find(l => Array.isArray(l) && l.length > 0) ?? []
}
