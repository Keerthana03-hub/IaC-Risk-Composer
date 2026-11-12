/**
 * ThemeContext.jsx
 * ----------------
 * Complete accessibility and appearance theme provider supporting:
 * - 'light'  : Clean, high-contrast white surfaces
 * - 'dark'   : Modern developer dark mode (slate-950/slate-900 surfaces)
 * - 'system' : Real-time sync with OS prefers-color-scheme
 *
 * Persists immediately in localStorage ('iac_theme_mode') and synchronizes
 * with developer profile preferences in the backend.
 */

import React, { createContext, useContext, useEffect, useState } from 'react'
import { safeStorage } from '../utils/storage'

const THEME_STORAGE_KEY = 'iac_theme_mode'
const ThemeContext = createContext(null)

function getSystemPrefersDark() {
  if (typeof window === 'undefined' || !window.matchMedia) return false
  return window.matchMedia('(prefers-color-scheme: dark)').matches
}

export function ThemeProvider({ children }) {
  // mode: 'light' | 'dark' | 'system'
  const [theme, setThemeState] = useState(() => {
    const saved = safeStorage.get(THEME_STORAGE_KEY)
    if (saved === 'dark' || saved === 'light' || saved === 'system') {
      return saved
    }
    return 'light'
  })

  const [systemIsDark, setSystemIsDark] = useState(getSystemPrefersDark)

  // Listen to OS prefers-color-scheme changes
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return

    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
    const handler = (e) => setSystemIsDark(e.matches)

    try {
      mediaQuery.addEventListener('change', handler)
      return () => mediaQuery.removeEventListener('change', handler)
    } catch {
      mediaQuery.addListener(handler)
      return () => mediaQuery.removeListener(handler)
    }
  }, [])

  // Calculate actual effective theme ('light' or 'dark')
  const resolvedTheme = theme === 'system' ? (systemIsDark ? 'dark' : 'light') : theme

  // Apply to document.documentElement
  useEffect(() => {
    const root = document.documentElement

    if (resolvedTheme === 'dark') {
      root.classList.add('dark')
      root.classList.remove('light')
      root.setAttribute('data-theme', 'dark')
      root.style.colorScheme = 'dark'
    } else {
      root.classList.remove('dark')
      root.classList.add('light')
      root.setAttribute('data-theme', 'light')
      root.style.colorScheme = 'light'
    }
  }, [resolvedTheme])

  function setTheme(newMode) {
    if (newMode !== 'light' && newMode !== 'dark' && newMode !== 'system') return
    setThemeState(newMode)
    safeStorage.set(THEME_STORAGE_KEY, newMode)
  }

  const value = {
    theme,
    resolvedTheme,
    systemIsDark,
    setTheme,
    isDark: resolvedTheme === 'dark',
  }

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme must be used within a ThemeProvider')
  return ctx
}
