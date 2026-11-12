import SidePanel from '../common/SidePanel'
import SeverityBadge from '../common/SeverityBadge'
import { ShieldAlert, Eye, Wrench, AlertOctagon, Info, AlertTriangle } from 'lucide-react'

function Section({ icon: Icon, title, children }) {
  return (
    <div className="mb-6 last:mb-0">
      <h4 className="flex items-center gap-2 text-xs font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider mb-2">
        <Icon className="h-3.5 w-3.5 text-blue-600 dark:text-blue-400" /> {title}
      </h4>
      {children}
    </div>
  )
}

export default function ThreatDetailPanel({ view, onClose }) {
  if (!view) return null
  const ra = view.finding.risk_assessment || {}

  return (
    <SidePanel
      open={!!view}
      onClose={onClose}
      title={view.title}
      subtitle={view.resourceId}
      badge={<SeverityBadge severity={view.severity} size="lg" />}
    >
      <Section icon={Info} title="Finding Explanation">
        <p className="text-xs sm:text-sm text-slate-800 dark:text-slate-200 leading-relaxed font-medium">
          {view.explanation?.summary || view.description || 'No explanation available.'}
        </p>
        {view.explanation?.why_it_matters && (
          <div className="mt-3 p-3 bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 rounded-lg">
            <span className="text-[11px] font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider block mb-1">
              Why It Matters
            </span>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              {view.explanation.why_it_matters}
            </p>
          </div>
        )}
      </Section>

      {view.impact && (
        <Section icon={AlertOctagon} title="Security Impact">
          <p className="text-xs sm:text-sm text-slate-700 dark:text-slate-300 leading-relaxed">
            {view.impact}
          </p>
        </Section>
      )}

      {view.attackScenario && (
        <Section icon={ShieldAlert} title="Attack Scenario">
          <p className="text-xs sm:text-sm text-slate-700 dark:text-slate-300 leading-relaxed">
            {view.attackScenario}
          </p>
        </Section>
      )}

      <Section icon={Eye} title="Risk Assessment">
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div className="inset-box p-3 bg-slate-50 dark:bg-slate-950/70 border-slate-200 dark:border-slate-800">
            <span className="text-slate-500 dark:text-slate-400 block mb-0.5 text-[11px]">Likelihood</span>
            <span className="text-slate-900 dark:text-slate-100 font-bold">
              {ra.likelihood ?? 'Not Assessed'}{ra.likelihood ? ' / 5' : ''}
            </span>
          </div>
          <div className="inset-box p-3 bg-slate-50 dark:bg-slate-950/70 border-slate-200 dark:border-slate-800">
            <span className="text-slate-500 dark:text-slate-400 block mb-0.5 text-[11px]">Impact Score</span>
            <span className="text-slate-900 dark:text-slate-100 font-bold">
              {ra.impact ?? 'Not Assessed'}{ra.impact ? ' / 5' : ''}
            </span>
          </div>
          <div className="inset-box p-3 bg-slate-50 dark:bg-slate-950/70 border-slate-200 dark:border-slate-800">
            <span className="text-slate-500 dark:text-slate-400 block mb-0.5 text-[11px]">Inherent Risk</span>
            <span className="text-slate-900 dark:text-slate-100 font-bold">
              {ra.inherent_risk_score ?? '—'}{ra.inherent_risk_score ? ' / 25' : ''}
            </span>
          </div>
          <div className="inset-box p-3 bg-slate-50 dark:bg-slate-950/70 border-slate-200 dark:border-slate-800">
            <span className="text-slate-500 dark:text-slate-400 block mb-0.5 text-[11px]">Confidence</span>
            <span className="text-slate-900 dark:text-slate-100 font-bold">
              {view.finding.confidence || '—'}
            </span>
          </div>
        </div>
        {ra.scoring_explanation && (
          <p className="text-[11px] text-slate-500 dark:text-slate-400 italic mt-2">
            {ra.scoring_explanation}
          </p>
        )}
      </Section>

      {view.controls.length > 0 && (
        <Section icon={Wrench} title="Recommended Controls">
          <ul className="space-y-2">
            {view.controls.map((c, i) => (
              <li key={i} className="text-xs text-slate-800 dark:text-slate-200 flex gap-2 font-medium">
                <span className="text-emerald-600 dark:text-emerald-400 font-bold flex-shrink-0 mt-0.5">&bull;</span>
                <span>{c}</span>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {view.remediations.map(rem => rem.suggested_code && (
        <Section key={rem.remediation_id} icon={Wrench} title="Suggested Terraform Patch">
          <p className="text-xs text-slate-600 dark:text-slate-400 mb-2">{rem.explanation}</p>
          <pre className="p-3 text-xs font-mono text-emerald-400 dark:text-emerald-300 bg-slate-900 border border-slate-800 rounded-xl overflow-x-auto leading-relaxed">
            <code>{rem.suggested_code}</code>
          </pre>
          <div className="mt-2 text-[11px] text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/50 border border-amber-200 dark:border-amber-800 rounded-lg p-2 flex items-center gap-1.5 font-medium">
            <AlertTriangle className="h-3.5 w-3.5 text-amber-500 flex-shrink-0" />
            Suggestion only — review before use. Never applied automatically.
          </div>
        </Section>
      ))}
    </SidePanel>
  )
}
