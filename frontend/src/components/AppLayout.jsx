/**
 * AppLayout.jsx
 * --------------
 * Persistent shell rendered for every authenticated page: collapsible
 * sidebar + top bar + routed page content.
 * Wraps everything in AnalysisProvider for workspace state sharing.
 */

import React, { useEffect, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import Sidebar from './layout/Sidebar'
import Topbar from './layout/Topbar'
import { AnalysisProvider } from '../context/AnalysisContext'
import { getHealth } from '../api'
import { safeStorage } from '../utils/storage'

export default function AppLayout() {
  const location = useLocation()
  const [collapsed, setCollapsed] = useState(() => safeStorage.get('sidebar_collapsed') === '1')
  const [mobileOpen, setMobileOpen] = useState(false)
  const [apiStatus, setApiStatus] = useState({ state: 'checking' })

  useEffect(() => {
    safeStorage.set('sidebar_collapsed', collapsed ? '1' : '0')
  }, [collapsed])

  useEffect(() => {
    setMobileOpen(false)
  }, [location.pathname])

  useEffect(() => {
    let cancelled = false
    function poll() {
      getHealth()
        .then(data => {
          if (!cancelled) setApiStatus({ state: 'ok', label: `API v${data.version}` })
        })
        .catch(() => {
          if (!cancelled) setApiStatus({ state: 'down' })
        })
    }
    poll()
    const id = setInterval(poll, 30000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  return (
    <AnalysisProvider>
      <div className="flex h-full bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-100 transition-colors duration-200">
        <Sidebar
          collapsed={collapsed}
          onToggle={() => setCollapsed(c => !c)}
          mobileOpen={mobileOpen}
          onCloseMobile={() => setMobileOpen(false)}
        />

        <div className="flex-1 flex flex-col min-w-0 h-full">
          <Topbar onToggleMobile={() => setMobileOpen(true)} apiStatus={apiStatus} />
          <main className="flex-1 overflow-y-auto">
            <div key={location.pathname} className="max-w-[1600px] mx-auto p-4 sm:p-6 lg:p-8 animate-fade-in">
              <Outlet />
            </div>
          </main>
        </div>
      </div>
    </AnalysisProvider>
  )
}
