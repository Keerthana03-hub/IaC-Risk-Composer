/**
 * Sidebar.jsx
 * -----------
 * Clean, professional SaaS sidebar with light & dark theme support.
 * Categorized into WORKSPACE, SECURITY, and SYSTEM sections.
 * Displays active workspace, navigation items, current developer's avatar, and quick logout.
 */

import React from 'react'
import { NavLink } from 'react-router-dom'
import {
  ShieldCheck,
  ChevronsLeft,
  ChevronsRight,
  LogOut,
  FolderGit2,
} from 'lucide-react'
import { NAV_SECTIONS } from '../../config/navigation'
import { useAuth } from '../../context/AuthContext'
import { useAnalysis } from '../../context/AnalysisContext'

export default function Sidebar({ collapsed, onToggle, mobileOpen, onCloseMobile }) {
  const { user, logout } = useAuth()
  const { currentProject } = useAnalysis()

  const initials = (user?.full_name || user?.username || 'D')
    .split(' ')
    .map(p => p[0])
    .join('')
    .slice(0, 2)
    .toUpperCase()

  return (
    <>
      {/* Mobile scrim */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-slate-900/40 backdrop-blur-sm lg:hidden animate-fade-in"
          onClick={onCloseMobile}
        />
      )}

      <aside
        className={`fixed lg:static inset-y-0 left-0 z-40 flex flex-col bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800
          transition-all duration-200 ease-out shadow-sm
          ${collapsed ? 'lg:w-[72px]' : 'lg:w-64'}
          ${mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'} w-64`}
      >
        {/* Brand */}
        <div className={`flex items-center gap-3 px-4 h-16 border-b border-slate-200 dark:border-slate-800 flex-shrink-0 ${collapsed ? 'lg:justify-center lg:px-0' : ''}`}>
          <div className="h-9 w-9 rounded-xl bg-blue-600 flex items-center justify-center flex-shrink-0 shadow-sm shadow-blue-500/30">
            <ShieldCheck className="h-5 w-5 text-white" strokeWidth={2.2} />
          </div>
          <div className={`min-w-0 ${collapsed ? 'lg:hidden' : ''}`}>
            <p className="text-sm font-bold text-slate-900 dark:text-white leading-tight truncate">IaC Risk Composer</p>
            <p className="text-[10px] text-slate-500 dark:text-slate-400 font-medium leading-tight truncate">Threat Model-as-Code</p>
          </div>
        </div>

        {/* Current Active Workspace Indicator */}
        {!collapsed && currentProject && (
          <div className="px-4 py-2.5 bg-slate-50 dark:bg-slate-950/80 border-b border-slate-100 dark:border-slate-800 flex items-center gap-2 text-xs">
            <FolderGit2 className="h-3.5 w-3.5 text-blue-600 dark:text-blue-400 flex-shrink-0" />
            <div className="min-w-0 flex-1">
              <span className="text-[10px] text-slate-400 dark:text-slate-500 uppercase font-semibold tracking-wider block">Active Workspace</span>
              <p className="text-slate-800 dark:text-slate-200 font-medium truncate">{currentProject.name}</p>
            </div>
          </div>
        )}

        {/* Navigation Sections */}
        <nav className="flex-1 overflow-y-auto py-3 px-3 space-y-4">
          {NAV_SECTIONS.map((section) => (
            <div key={section.title} className="space-y-1">
              {!collapsed && (
                <span className="text-[10px] font-semibold text-slate-400 dark:text-slate-500 tracking-wider px-2 py-1 block">
                  {section.title}
                </span>
              )}
              {section.items.map(({ to, path, label, icon: Icon }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={false}
                  onClick={onCloseMobile}
                  className={({ isActive: rrIsActive }) => {
                    const active = path ? window.location.pathname === path : rrIsActive
                    return `group relative flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-semibold
                      transition-all duration-150
                      ${
                        active
                          ? 'bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 dark:border dark:border-blue-800/60 shadow-xs'
                          : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100/80 dark:hover:bg-slate-800/80 hover:text-slate-900 dark:hover:text-slate-100'
                      }
                      ${collapsed ? 'lg:justify-center' : ''}`
                  }}
                  title={collapsed ? label : undefined}
                >
                  <Icon className="h-4 w-4 flex-shrink-0" />
                  <span className={collapsed ? 'lg:hidden' : ''}>{label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        {/* Collapse toggle (desktop only) */}
        <button
          onClick={onToggle}
          className="hidden lg:flex items-center justify-center gap-2 mx-3 mb-2 py-1.5 rounded-lg text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors text-xs font-medium"
        >
          {collapsed ? <ChevronsRight className="h-4 w-4" /> : <><ChevronsLeft className="h-4 w-4" /> Collapse Sidebar</>}
        </button>

        {/* Developer Account Badge */}
        <div className="border-t border-slate-200 dark:border-slate-800 p-3 flex-shrink-0 bg-slate-50/60 dark:bg-slate-950/60">
          <div className={`flex items-center gap-2.5 ${collapsed ? 'lg:justify-center' : ''}`}>
            <div className="h-9 w-9 rounded-full bg-blue-100 dark:bg-blue-950 border border-blue-200 dark:border-blue-800 flex items-center justify-center text-xs font-bold text-blue-700 dark:text-blue-300 flex-shrink-0 shadow-xs">
              {initials}
            </div>
            <div className={`min-w-0 flex-1 ${collapsed ? 'lg:hidden' : ''}`}>
              <p className="text-xs font-semibold text-slate-900 dark:text-slate-100 truncate">
                {user?.full_name || user?.username || 'Developer'}
              </p>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                {user?.email || user?.organization || 'Personal Workspace'}
              </p>
            </div>
            <button
              onClick={logout}
              className={`icon-btn hover:text-rose-600 dark:hover:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/50 flex-shrink-0 ${collapsed ? 'lg:hidden' : ''}`}
              title="Sign Out"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>
    </>
  )
}
