/** localStorage/sessionStorage can throw (private mode, blocked cookies) – never let that break the UI. */
export const safeStorage = {
  get(key, fallback = null, area = 'localStorage') {
    try { const v = window[area].getItem(key); return v === null ? fallback : v } catch { return fallback }
  },
  set(key, value, area = 'localStorage') {
    try { window[area].setItem(key, value) } catch { /* ignore */ }
  },
  remove(key, area = 'localStorage') {
    try { window[area].removeItem(key) } catch { /* ignore */ }
  },
}
