import { useCallback, useRef, useState } from 'react'
import { UploadCloud, FileCode2, X, CheckCircle2 } from 'lucide-react'
import { formatBytes } from '../../utils/format'

export default function UploadArea({ selectedFile, onSelect, onClear, error }) {
  const inputRef = useRef(null)
  const [dragOver, setDragOver] = useState(false)

  const handleFiles = useCallback((files) => {
    const file = files?.[0]
    if (!file) return
    onSelect(file)
  }, [onSelect])

  return (
    <div>
      <div
        onDragOver={e => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={e => { e.preventDefault(); setDragOver(false); handleFiles(e.dataTransfer.files) }}
        onClick={() => inputRef.current?.click()}
        className={`relative flex flex-col items-center justify-center gap-3 text-center rounded-2xl border-2 border-dashed
          px-6 py-10 sm:py-12 cursor-pointer transition-all duration-150
          ${
            dragOver
              ? 'border-blue-500 bg-blue-50/70 dark:bg-blue-950/40 shadow-sm'
              : 'border-slate-300 dark:border-slate-700 hover:border-blue-400 dark:hover:border-blue-500 hover:bg-slate-50/80 dark:hover:bg-slate-900/60 bg-white dark:bg-slate-900/90'
          }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".tf"
          onChange={e => handleFiles(e.target.files)}
          className="hidden"
        />
        <div className="h-16 w-16 rounded-2xl bg-blue-50 dark:bg-blue-950/60 border border-blue-100 dark:border-blue-900/60 flex items-center justify-center shadow-xs">
          <UploadCloud className="h-8 w-8 text-blue-600 dark:text-blue-400" />
        </div>
        <div>
          <p className="text-sm font-bold text-slate-900 dark:text-slate-100">
            Drag & drop your infrastructure configuration here
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            or <span className="text-blue-600 dark:text-blue-400 font-semibold hover:underline">browse files</span> on your computer
          </p>
        </div>

        <div className="flex items-center gap-2 pt-2 text-[11px] text-slate-500 dark:text-slate-400">
          <span className="font-semibold text-slate-700 dark:text-slate-300">Supported:</span>
          <span className="bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded font-mono text-slate-700 dark:text-slate-300 font-medium">Terraform (.tf)</span>
          <span className="bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded text-slate-500 dark:text-slate-400">CloudFormation (planned)</span>
          <span className="bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded text-slate-500 dark:text-slate-400">Kubernetes (planned)</span>
        </div>
      </div>

      {selectedFile && (
        <div className="flex items-center gap-3.5 mt-4 p-4 rounded-xl bg-blue-50/60 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800/80 animate-slide-up">
          <div className="h-10 w-10 rounded-lg bg-blue-100 dark:bg-blue-900/80 flex items-center justify-center text-blue-700 dark:text-blue-300 flex-shrink-0">
            <FileCode2 className="h-5 w-5" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <p className="text-sm font-bold text-slate-900 dark:text-slate-100 font-mono truncate">{selectedFile.name}</p>
              <span className="inline-flex items-center gap-1 text-[10px] font-bold text-emerald-700 dark:text-emerald-300 bg-emerald-100 dark:bg-emerald-950/80 px-2 py-0.5 rounded-full">
                <CheckCircle2 className="h-3 w-3" /> Valid Terraform
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 font-medium">
              Ready for static threat analysis &middot; {formatBytes(selectedFile.size)}
            </p>
          </div>
          <button
            onClick={(e) => {
              e.stopPropagation()
              onClear()
            }}
            className="icon-btn hover:bg-blue-100 dark:hover:bg-blue-900/60 hover:text-slate-800 dark:hover:text-slate-200 flex-shrink-0"
            aria-label="Remove file"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {error && (
        <p className="text-rose-700 dark:text-rose-300 text-xs bg-rose-50 dark:bg-rose-950/50 border border-rose-200 dark:border-rose-900/60 rounded-lg px-3.5 py-2.5 mt-4 animate-fade-in font-medium">
          {error}
        </p>
      )}
    </div>
  )
}
