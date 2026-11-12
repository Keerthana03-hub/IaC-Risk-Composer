import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { SEVERITY_META } from '../../utils/risk'
import EmptyState from '../common/EmptyState'
import { Target } from 'lucide-react'
import { useTheme } from '../../context/ThemeContext'

/** Stacked horizontal bar: which resources carry the most findings, by severity. */
export default function ThreatsByResourceChart({ rows }) {
  const { isDark } = useTheme()

  if (!rows || rows.length === 0) {
    return (
      <div className="card">
        <h3 className="section-title mb-1">Findings by Resource</h3>
        <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">Which resources carry the most detected findings.</p>
        <EmptyState icon={Target} title="No findings to rank" description="Findings will appear here once an analysis detects them." />
      </div>
    )
  }
  const top = rows.slice(0, 8)

  return (
    <div className="card">
      <h3 className="section-title mb-1">Findings by Resource</h3>
      <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">Which resources carry the most detected findings.</p>
      <ResponsiveContainer width="100%" height={Math.max(220, top.length * 38)}>
        <BarChart data={top} layout="vertical" margin={{ left: 8, right: 16, top: 4, bottom: 4 }} barCategoryGap={12}>
          <CartesianGrid strokeDasharray="3 3" stroke={isDark ? '#1e293b' : '#f1f5f9'} horizontal={false} />
          <XAxis
            type="number"
            allowDecimals={false}
            stroke={isDark ? '#64748b' : '#94a3b8'}
            fontSize={11}
            tickLine={false}
            axisLine={{ stroke: isDark ? '#334155' : '#e2e8f0' }}
          />
          <YAxis
            type="category"
            dataKey="name"
            stroke={isDark ? '#94a3b8' : '#475569'}
            fontSize={11}
            width={130}
            tickLine={false}
            axisLine={false}
          />
          <Tooltip
            cursor={{ fill: isDark ? 'rgba(59, 130, 246, 0.1)' : 'rgba(37, 99, 235, 0.04)' }}
            contentStyle={{
              background: isDark ? '#0f172a' : '#ffffff',
              border: isDark ? '1px solid #334155' : '1px solid #e2e8f0',
              boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.2)',
              borderRadius: 10,
              fontSize: 12,
            }}
            labelStyle={{ color: isDark ? '#f8fafc' : '#0f172a', fontWeight: 600 }}
            itemStyle={{ color: isDark ? '#cbd5e1' : '#334155' }}
          />
          <Bar dataKey="critical" stackId="s" fill={SEVERITY_META.critical.color} name="Critical" animationDuration={700} />
          <Bar dataKey="high"     stackId="s" fill={SEVERITY_META.high.color}     name="High" animationDuration={700} />
          <Bar dataKey="medium"   stackId="s" fill={SEVERITY_META.medium.color}   name="Medium" animationDuration={700} />
          <Bar dataKey="low"      stackId="s" fill={SEVERITY_META.low.color}      name="Low" radius={[0, 6, 6, 0]} animationDuration={700} />
          <Bar dataKey="info"     stackId="s" fill={SEVERITY_META.info.color}     name="Info" animationDuration={700} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
