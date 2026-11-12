/**
 * Turn thrown errors into short, user-facing copy. Raw backend payloads
 * ("API GET /x → 500: {...}") and stack traces are never shown.
 */
export function friendlyError(err, fallback = 'Something went wrong. Please try again.') {
  const msg = String(err?.message ?? '')
  if (!msg) return fallback
  if (/failed to fetch|networkerror|load failed/i.test(msg)) {
    return 'Unable to reach the analysis service. Make sure the backend is running and try again.'
  }
  if (/^API (GET|POST|DELETE|PUT)/.test(msg) || /traceback|<html/i.test(msg)) return fallback
  return msg.length > 300 ? fallback : msg
}
