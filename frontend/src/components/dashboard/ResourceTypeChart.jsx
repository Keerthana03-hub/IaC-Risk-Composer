import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid } from 'recharts'
import EmptyState from '../common/EmptyState'
import { Boxes } from 'lucide-react'
import { useTheme } from '../../context/ThemeContext'

export default function ResourceTypeChart({ data }) {
  const { isDark } = useTheme()

  if (!data || data.length === 0) {
    return (
      <div className="card">
        <h3 className="section-title mb-1">Infrastructure Resource Types</h3>
        <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">Resource blocks detected in the analyzed Terraform file.</p>
        <EmptyState icon={Boxes} title="No resources yet" description="Upload a Terraform file to see the resource breakdown." />
      </div>
    )
  }

  return (
    <div className="card">
      <h3 className="section-title mb-1">Infrastructure Resource Types</h3>
      <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">Resource blocks detected in the analyzed Terraform file.</p>
      <ResponsiveContainer width="100%" height={Math.max(220, data.length * 34)}>
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16, top: 4, bottom: 4 }} barCategoryGap={10}>
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
            dataKey="type"
            stroke={isDark ? '#94a3b8' : '#475569'}
            fontSize={11}
            width={150}
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
          <Bar dataKey="count" radius={[0, 6, 6, 0]} animationDuration={700}>
            {data.map((_, i) => <Cell key={i} fill="#3b82f6" fillOpacity={0.9} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
