/**
 * Topbar.jsx
 * ----------
 * Modern SaaS Top Bar with full Light and Dark theme support.
 * Features:
 * - Dynamic page breadcrumbs
 * - Active Workspace / Project selector dropdown
 * - Global quick-search input
 * - Live backend health indicator
 * - Quick Theme Toggle (Light / Dark / System)
 * - Notifications dropdown
 * - User profile dropdown with Sign Out
 * - "+ New Analysis" primary action button
 */

import React, { useState, useRef, useEffect } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import {
  Menu,
  Plus,
  ShieldCheck,
  WifiOff,
  Loader2,
  Search,
  Bell,
  FolderGit2,
  ChevronDown,
  User,
  Settings as SettingsIcon,
  LogOut,
  ExternalLink,
  CheckCircle,
  Sun,
  Moon,
  Laptop,
} from 'lucide-react'
import { pageMeta } from '../../config/navigation'
import { useAuth } from '../../context/AuthContext'
import { useAnalysis } from '../../context/AnalysisContext'
import { useTheme } from '../../context/ThemeContext'

export default function Topbar({ onToggleMobile, apiStatus }) {
  const location = useLocation()
  const navigate = useNavigate()
  const { user, logout } = useAuth()
  const { projects, currentProjectId, selectProject } = useAnalysis()
  const { theme, resolvedTheme, setTheme } = useTheme()

  const meta = pageMeta(location.pathname)

  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const [notifOpen, setNotifOpen] = useState(false)
  const [themeMenuOpen, setThemeMenuOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')

  const userMenuRef = useRef(null)
  const notifRef = useRef(null)
  const themeMenuRef = useRef(null)

  // Close dropdowns on outside click
  useEffect(() => {
    function handleClickOutside(e) {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target)) {
        setUserMenuOpen(false)
      }
      if (notifRef.current && !notifRef.current.contains(e.target)) {
        setNotifOpen(false)
      }
      if (themeMenuRef.current && !themeMenuRef.current.contains(e.target)) {
        setThemeMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  function handleSearchSubmit(e) {
    e.preventDefault()
    if (searchQuery.trim()) {
      navigate(`/threats?q=${encodeURIComponent(searchQuery.trim())}`)
      setSearchQuery('')
    }
  }

  const initials = (user?.full_name || user?.username || 'D')
    .split(' ')
    .map(p => p[0])
    .join('')
    .slice(0, 2)
    .toUpperCase()

  return (
    <header className="sticky top-0 z-20 flex items-center justify-between h-16 px-4 sm:px-6 border-b border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-slate-900/95 backdrop-blur shadow-xs transition-colors duration-200">
      {/* Left: Mobile hamburger & Page Title */}
      <div className="flex items-center gap-3 min-w-0">
        <button
          onClick={onToggleMobile}
          className="icon-btn lg:hidden"
          aria-label="Open menu"
        >
          <Menu className="h-5 w-5" />
        </button>

        <div className="min-w-0">
          <h1 className="text-sm sm:text-base font-bold text-slate-900 dark:text-slate-100 truncate tracking-tight">
            {meta.title}
          </h1>
          <p className="hidden sm:block text-[11px] text-slate-500 dark:text-slate-400 truncate">
            {meta.description}
          </p>
        </div>
      </div>

      {/* Center: Search & Project Selector */}
      <div className="hidden md:flex items-center gap-3 max-w-md w-full mx-4">
        {/* Workspace Project Selector */}
        {projects.length > 0 && (
          <div className="relative flex-shrink-0">
            <select
              value={currentProjectId || ''}
              onChange={e => selectProject(e.target.value)}
              className="appearance-none bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs font-semibold text-slate-700 dark:text-slate-200 rounded-lg pl-8 pr-7 py-2 cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-900 transition-colors focus:ring-2 focus:ring-blue-500/20 outline-none"
              title="Select Active Project Workspace"
            >
              {projects.map(p => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
            <FolderGit2 className="h-3.5 w-3.5 text-blue-600 dark:text-blue-400 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <ChevronDown className="h-3.5 w-3.5 text-slate-400 absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none" />
          </div>
        )}

        {/* Global Search */}
        <form onSubmit={handleSearchSubmit} className="relative flex-1">
          <Search className="h-3.5 w-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search threats, findings, resources..."
            className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs text-slate-800 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 rounded-lg pl-8 pr-3 py-1.5 focus:bg-white dark:focus:bg-slate-900 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 outline-none transition-all"
          />
        </form>
      </div>

      {/* Right Actions */}
      <div className="flex items-center gap-2 sm:gap-2.5 flex-shrink-0">
        <ApiStatusPill status={apiStatus} />

        {/* Quick Theme Selector Dropdown */}
        <div className="relative" ref={themeMenuRef}>
          <button
            onClick={() => setThemeMenuOpen(!themeMenuOpen)}
            className="icon-btn hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300"
            title={`Current theme: ${theme} (${resolvedTheme})`}
            aria-label="Toggle theme"
          >
            {theme === 'system' ? (
              <Laptop className="h-4 w-4" />
            ) : resolvedTheme === 'dark' ? (
              <Moon className="h-4 w-4 text-blue-400" />
            ) : (
              <Sun className="h-4 w-4 text-amber-500" />
            )}
          </button>

          {themeMenuOpen && (
            <div className="absolute right-0 mt-2 w-40 bg-white dark:bg-slate-900 rounded-xl shadow-lg border border-slate-200 dark:border-slate-800 p-1.5 z-50 animate-pop-in text-xs">
              <div className="px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                Appearance
              </div>
              <button
                onClick={() => {
                  setTheme('light')
                  setThemeMenuOpen(false)
                }}
                className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg font-medium transition-colors text-left ${
                  theme === 'light'
                    ? 'bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 font-semibold'
                    : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                <Sun className="h-3.5 w-3.5 text-amber-500" />
                <span>Light</span>
              </button>
              <button
                onClick={() => {
                  setTheme('dark')
                  setThemeMenuOpen(false)
                }}
                className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg font-medium transition-colors text-left ${
                  theme === 'dark'
                    ? 'bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 font-semibold'
                    : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                <Moon className="h-3.5 w-3.5 text-blue-400" />
                <span>Dark</span>
              </button>
              <button
                onClick={() => {
                  setTheme('system')
                  setThemeMenuOpen(false)
                }}
                className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg font-medium transition-colors text-left ${
                  theme === 'system'
                    ? 'bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 font-semibold'
                    : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                <Laptop className="h-3.5 w-3.5 text-slate-400" />
                <span>System Sync</span>
              </button>
            </div>
          )}
        </div>

        {/* Notifications Dropdown */}
        <div className="relative" ref={notifRef}>
          <button
            onClick={() => setNotifOpen(!notifOpen)}
            className="icon-btn relative hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300"
            title="Notifications"
          >
            <Bell className="h-4 w-4" />
            <span className="absolute top-1.5 right-1.5 h-2 w-2 rounded-full bg-blue-600 ring-2 ring-white dark:ring-slate-900" />
          </button>

          {notifOpen && (
            <div className="absolute right-0 mt-2 w-80 bg-white dark:bg-slate-900 rounded-xl shadow-lg border border-slate-200 dark:border-slate-800 p-3 z-50 animate-pop-in">
              <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-2 mb-2">
                <span className="text-xs font-bold text-slate-800 dark:text-slate-200">Workspace Alerts</span>
                <span className="text-[10px] bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300 font-semibold px-2 py-0.5 rounded-full">
                  Live
                </span>
              </div>
              <div className="space-y-2 text-xs">
                <div className="p-2 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-100 dark:border-slate-800">
                  <div className="flex items-center gap-1.5 text-emerald-700 dark:text-emerald-400 font-semibold mb-0.5">
                    <CheckCircle className="h-3.5 w-3.5" /> Engine Active
                  </div>
                  <p className="text-slate-600 dark:text-slate-400 text-[11px]">
                    Multi-developer workspace loaded and connected to SQLite storage.
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Primary CTA */}
        <Link
          to="/analyze?new=1"
          className="btn-primary text-xs py-2 px-3 shadow-sm font-semibold"
        >
          <Plus className="h-4 w-4" />
          <span className="hidden sm:inline">New Analysis</span>
        </Link>

        {/* User Account Menu */}
        <div className="relative" ref={userMenuRef}>
          <button
            onClick={() => setUserMenuOpen(!userMenuOpen)}
            className="flex items-center gap-2 p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <div className="h-8 w-8 rounded-full bg-blue-100 dark:bg-blue-950 border border-blue-200 dark:border-blue-800 flex items-center justify-center text-xs font-bold text-blue-700 dark:text-blue-300 shadow-xs">
              {initials}
            </div>
            <ChevronDown className="h-3.5 w-3.5 text-slate-400 hidden sm:block" />
          </button>

          {userMenuOpen && (
            <div className="absolute right-0 mt-2 w-56 bg-white dark:bg-slate-900 rounded-xl shadow-lg border border-slate-200 dark:border-slate-800 py-1.5 z-50 animate-pop-in">
              <div className="px-3 py-2 border-b border-slate-100 dark:border-slate-800">
                <p className="text-xs font-bold text-slate-900 dark:text-slate-100 truncate">
                  {user?.full_name || user?.username}
                </p>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                  {user?.email}
                </p>
                <span className="inline-block mt-1 text-[10px] font-semibold bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 px-1.5 py-0.5 rounded">
                  {user?.organization || 'Developer'}
                </span>
              </div>

              <div className="py-1 text-xs">
                <Link
                  to="/settings"
                  onClick={() => setUserMenuOpen(false)}
                  className="flex items-center gap-2.5 px-3 py-2 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
                >
                  <User className="h-4 w-4 text-slate-400" /> Profile & Credentials
                </Link>
                <Link
                  to="/settings"
                  onClick={() => setUserMenuOpen(false)}
                  className="flex items-center gap-2.5 px-3 py-2 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
                >
                  <SettingsIcon className="h-4 w-4 text-slate-400" /> Preferences
                </Link>
                <Link
                  to="/system-info"
                  onClick={() => setUserMenuOpen(false)}
                  className="flex items-center gap-2.5 px-3 py-2 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
                >
                  <ExternalLink className="h-4 w-4 text-slate-400" /> System Architecture
                </Link>
              </div>

              <div className="border-t border-slate-100 dark:border-slate-800 pt-1">
                <button
                  onClick={() => {
                    setUserMenuOpen(false)
                    logout()
                  }}
                  className="w-full flex items-center gap-2.5 px-3 py-2 text-xs font-semibold text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/40 transition-colors"
                >
                  <LogOut className="h-4 w-4" /> Sign Out
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}

function ApiStatusPill({ status }) {
  const state = status?.state || 'checking'
  const cfg = {
    ok: {
      icon: ShieldCheck,
      cls: 'text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/60 border-emerald-200 dark:border-emerald-800',
      label: status?.label || 'API v1.0.0',
    },
    checking: {
      icon: Loader2,
      cls: 'text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 border-slate-200 dark:border-slate-700',
      label: 'Connecting…',
    },
    down: {
      icon: WifiOff,
      cls: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/60 border-rose-200 dark:border-rose-800',
      label: 'API Disconnected',
    },
  }[state]

  const Icon = cfg.icon
  return (
    <span
      className={`hidden md:inline-flex items-center gap-1.5 text-[11px] font-semibold px-2.5 py-1 rounded-full border shadow-2xs ${cfg.cls}`}
    >
      <Icon className={`h-3 w-3 ${state === 'checking' ? 'animate-spin' : ''}`} />
      {cfg.label}
    </span>
  )
}
