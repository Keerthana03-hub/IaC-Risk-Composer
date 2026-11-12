import { useEffect, useState } from 'react'
import { Check, Loader2, Circle } from 'lucide-react'

// Section 20: Professional analysis progress stepper
const STEPS = [
  'Upload received',
  'Parsing configuration',
  'Mapping infrastructure',
  'Detecting threats',
  'Calculating risk',
  'Generating report',
]

export default function AnalysisProgress({ active, done }) {
  const [step, setStep] = useState(0)

  useEffect(() => {
    if (!active) {
      setStep(0)
      return
    }
    const id = setInterval(() => {
      setStep(s => (s < STEPS.length - 1 ? s + 1 : s))
    }, 450)
    return () => clearInterval(id)
  }, [active])

  useEffect(() => {
    if (done) setStep(STEPS.length)
  }, [done])

  if (!active) return null

  return (
    <div className="card p-6 border-blue-200 dark:border-blue-900/50 bg-blue-50/20 dark:bg-blue-950/20 animate-fade-in shadow-md">
      <div className="flex items-center gap-3 mb-5 border-b border-slate-100 dark:border-slate-800 pb-3">
        <div className="h-9 w-9 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-xs">
          <Loader2 className="h-5 w-5 animate-spin" />
        </div>
        <div>
          <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">Analyzing Infrastructure</h3>
          <p className="text-xs text-slate-500 dark:text-slate-400">Automated static analysis, threat detection, and risk synthesis.</p>
        </div>
      </div>

      <ol className="space-y-3">
        {STEPS.map((label, i) => {
          const complete = i < step
          const current = i === step
          const pending = i > step

          return (
            <li key={label} className="flex items-center gap-3">
              <span
                className={`flex-shrink-0 h-6 w-6 rounded-full flex items-center justify-center text-xs font-bold transition-all duration-200
                  ${
                    complete
                      ? 'bg-emerald-100 dark:bg-emerald-950/80 text-emerald-700 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800'
                      : current
                      ? 'bg-blue-600 text-white shadow-sm ring-4 ring-blue-100 dark:ring-blue-900/50'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-400 dark:text-slate-500 border border-slate-200 dark:border-slate-700'
                  }`}
              >
                {complete ? (
                  <Check className="h-3.5 w-3.5 stroke-[2.5]" />
                ) : current ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Circle className="h-2 w-2" />
                )}
              </span>
              <span
                className={`text-xs ${
                  complete
                    ? 'text-slate-800 dark:text-slate-200 font-semibold'
                    : current
                    ? 'text-blue-700 dark:text-blue-400 font-bold'
                    : 'text-slate-400 dark:text-slate-500 font-medium'
                }`}
              >
                {label}
              </span>
            </li>
          )
        })}
      </ol>
    </div>
  )
}
