/**
 * App.jsx
 * --------
 * Top-level application router with multi-developer session protection.
 *
 * Route structure:
 *   /                → redirect to /dashboard (or /login if unauthenticated)
 *   /login           → Login page (public; redirects to /dashboard if logged in)
 *   /register        → Registration page (public; redirects to /dashboard if logged in)
 *   /dashboard       → Personalized developer dashboard (protected)
 *   /projects        → Multi-project workspace manager (protected)
 *   /analyze         → New IaC Security Analysis workbench (protected)
 *   /infrastructure  → Infrastructure Explorer / Architecture Map (protected)
 *   /threats         → STRIDE threat detection list & details (protected)
 *   /reports         → Security assessment reports & downloads (protected)
 *   /system-info     → System Architecture, scoring rules & engine (protected)
 *   /settings        → Developer Profile, Appearance & Preferences (protected)
 *   /history         → Legacy redirect to /projects
 */

import React from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'

import { AuthProvider, useAuth } from './context/AuthContext'
import { ThemeProvider } from './context/ThemeContext'
import AppLayout from './components/AppLayout'
import Login from './pages/Login'
import Register from './pages/Register'
import Dashboard from './pages/Dashboard'
import Projects from './pages/Projects'
import IacAnalysis from './pages/IacAnalysis'
import Infrastructure from './pages/Infrastructure'
import Threats from './pages/Threats'
import ThreatReports from './pages/ThreatReports'
import SystemInfo from './pages/SystemInfo'
import Settings from './pages/Settings'

// Guard wrapper – redirects unauthenticated visitors to /login
function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-slate-50 dark:bg-slate-950">
        <div className="flex flex-col items-center gap-3">
          <div className="w-9 h-9 border-3 border-blue-600 border-t-transparent rounded-full animate-spin" />
          <p className="text-xs font-semibold text-slate-600 dark:text-slate-300">Restoring workspace session…</p>
        </div>
      </div>
    )
  }

  return user ? children : <Navigate to="/login" replace />
}

// Public auth route guard – redirects already logged-in developers to /dashboard
function PublicAuthRoute({ children }) {
  const { user, loading } = useAuth()

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-slate-50 dark:bg-slate-950">
        <div className="w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  return user ? <Navigate to="/dashboard" replace /> : children
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <BrowserRouter>

        <Routes>
          {/* Public Auth routes */}
          <Route
            path="/login"
            element={
              <PublicAuthRoute>
                <Login />
              </PublicAuthRoute>
            }
          />
          <Route
            path="/register"
            element={
              <PublicAuthRoute>
                <Register />
              </PublicAuthRoute>
            }
          />

          {/* Protected – wrapped in the shared sidebar/topbar layout */}
          <Route
            element={
              <ProtectedRoute>
                <AppLayout />
              </ProtectedRoute>
            }
          >
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="projects" element={<Projects />} />
            <Route path="analyze" element={<IacAnalysis />} />
            <Route path="infrastructure" element={<Infrastructure />} />
            <Route path="threats" element={<Threats />} />
            <Route path="reports" element={<ThreatReports />} />
            <Route path="system-info" element={<SystemInfo />} />
            <Route path="settings" element={<Settings />} />

            {/* Backward-compatibility redirect for legacy bookmarks */}
            <Route path="history" element={<Navigate to="/projects" replace />} />
          </Route>

          {/* Catch-all */}
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
    </ThemeProvider>
  )
}


