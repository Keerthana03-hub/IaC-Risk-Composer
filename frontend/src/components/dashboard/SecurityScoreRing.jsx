import { useEffect, useState } from 'react'
import AnimatedNumber from '../common/AnimatedNumber'

const BAND_COLOR = { low: '#16a34a', medium: '#d97706', high: '#ea580c', critical: '#e11d48' }

/**
 * Large circular posture gauge for light & dark theme.
 */
export default function SecurityScoreRing({ score, band, label, size = 176, stroke = 14 }) {
  const [animated, setAnimated] = useState(0)
  const radius = (size - stroke) / 2
  const circumference = 2 * Math.PI * radius
  const hasScore = typeof score === 'number'

  useEffect(() => {
    if (!hasScore) { setAnimated(0); return }
    const t = requestAnimationFrame(() => setAnimated(score))
    return () => cancelAnimationFrame(t)
  }, [score, hasScore])

  const color = hasScore ? BAND_COLOR[band] : '#64748b'
  const offset = circumference - (animated / 100) * circumference

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            className="stroke-slate-100 dark:stroke-slate-800/90"
            strokeWidth={stroke}
          />
          {hasScore && (
            <circle
              cx={size / 2} cy={size / 2} r={radius} fill="none"
              stroke={color} strokeWidth={stroke} strokeLinecap="round"
              strokeDasharray={circumference} strokeDashoffset={offset}
              style={{ transition: 'stroke-dashoffset 900ms cubic-bezier(.4,0,.2,1), stroke 400ms' }}
            />
          )}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-extrabold text-slate-900 dark:text-slate-100 tracking-tight tabular-nums">
            {hasScore ? <AnimatedNumber value={score} /> : '—'}
          </span>
          <span className="text-[11px] text-slate-400 dark:text-slate-500 font-medium mt-0.5">/ 100</span>
        </div>
      </div>
      <p className="text-xs eyebrow mt-4">Security Score</p>
      <p className="text-sm font-bold mt-0.5" style={{ color: hasScore ? color : '#64748b' }}>
        {hasScore ? label : 'No data yet'}
      </p>
    </div>
  )
}
