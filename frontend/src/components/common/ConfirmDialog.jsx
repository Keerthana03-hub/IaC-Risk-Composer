import Modal from './Modal'

export default function ConfirmDialog({ open, title, message, confirmLabel = 'Delete', danger = true, onConfirm, onCancel, busy }) {
  return (
    <Modal open={open} onClose={onCancel} title={title} maxWidth="max-w-sm">
      <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">{message}</p>
      <div className="flex justify-end gap-2.5 mt-6 pt-3 border-t border-slate-100 dark:border-slate-800">
        <button className="btn-ghost text-xs py-2 px-3.5 font-semibold" onClick={onCancel} disabled={busy}>Cancel</button>
        <button className={danger ? 'btn-danger text-xs py-2 px-3.5 font-semibold' : 'btn-primary text-xs py-2 px-3.5 font-semibold'} onClick={onConfirm} disabled={busy}>
          {busy ? 'Processing…' : confirmLabel}
        </button>
      </div>
    </Modal>
  )
}
