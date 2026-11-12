import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { SEVERITY_META, SEVERITY_ORDER } from '../../utils/risk'
import EmptyState from '../common/EmptyState'
import { ShieldCheck } from 'lucide-react'
import { useTheme } from '../../context/ThemeContext'

export default function RiskDistributionChart({ counts }) {
  const { isDark } = useTheme()

  const data = SEVERITY_ORDER
    .filter(s => s !== 'info' || counts.info > 0)
    .map(s => ({ key: s, name: SEVERITY_META[s].label, value: counts[s] }))
    .filter(d => d.value > 0)

  if (!counts || counts.total === 0) {
    return (
      <div className="card">
        <h3 className="section-title mb-1">Risk Distribution</h3>
        <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">Findings by severity for the selected analysis.</p>
        <EmptyState icon={ShieldCheck} title="No findings to chart" description="Run or select an analysis with detected findings." />
      </div>
    )
  }

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-1">
        <h3 className="section-title">Risk Distribution</h3>
        <span className="text-xs font-semibold text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded-full">
          {counts.total} findings
        </span>
      </div>
      <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">Findings by severity for the selected analysis.</p>
      <ResponsiveContainer width="100%" height={240}>
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="name" innerRadius={60} outerRadius={90} paddingAngle={3} animationDuration={700}>
            {data.map(d => (
              <Cell
                key={d.key}
                fill={SEVERITY_META[d.key].color}
                stroke={isDark ? '#0f172a' : '#ffffff'}
                strokeWidth={2}
              />
            ))}
          </Pie>
          <Tooltip
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
          <Legend
            iconType="circle"
            iconSize={8}
            wrapperStyle={{ fontSize: 12, color: isDark ? '#94a3b8' : '#64748b' }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}
