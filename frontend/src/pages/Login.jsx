/**
 * Login.jsx
 * ----------
 * Professional SaaS Developer Login Screen.
 * Clean white/light background, split layout:
 * - Left: Brand, value proposition, abstract cloud security topology illustration
 * - Right: Sign in form with validation, remember me, demo credentials helper, and registration link
 */

import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  ShieldCheck,
  Lock,
  User,
  ArrowRight,
  Sparkles,
  CheckCircle2,
  Cpu,
  Layers,
  ShieldAlert,
} from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { friendlyError } from '../utils/errors'

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()

  const [usernameOrEmail, setUsernameOrEmail] = useState('')
  const [password, setPassword] = useState('')
  const [rememberMe, setRememberMe] = useState(true)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [showForgotModal, setShowForgotModal] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(usernameOrEmail, password, rememberMe)
      navigate('/dashboard')
    } catch (err) {
      setError(friendlyError(err, 'Invalid credentials. Please verify your username and password.'))
    } finally {
      setLoading(false)
    }
  }

  function handleFillDemo() {
    setUsernameOrEmail('admin')
    setPassword('admin')
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex flex-col justify-center lg:p-6 transition-colors">
      <div className="mx-auto w-full max-w-6xl bg-white dark:bg-slate-900 lg:rounded-2xl lg:shadow-xl lg:border lg:border-slate-200/80 dark:lg:border-slate-800 overflow-hidden flex flex-col lg:flex-row min-h-[640px]">
        
        {/* Left Side: Brand & Visual Proposition */}
        <div className="lg:w-1/2 bg-gradient-to-br from-blue-700 via-blue-800 to-indigo-900 p-8 lg:p-12 text-white flex flex-col justify-between relative overflow-hidden">
          {/* Subtle background abstract shapes */}
          <div className="absolute -top-24 -left-24 w-80 h-80 bg-blue-500/20 rounded-full blur-3xl pointer-events-none" />
          <div className="absolute -bottom-24 -right-24 w-96 h-96 bg-indigo-500/20 rounded-full blur-3xl pointer-events-none" />

          {/* Top Brand */}
          <div className="relative z-10">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-xl bg-white/10 backdrop-blur border border-white/20 flex items-center justify-center shadow-inner">
                <ShieldCheck className="h-6 w-6 text-blue-200" strokeWidth={2.2} />
              </div>
              <div>
                <span className="text-xl font-bold tracking-tight text-white block leading-tight">
                  IaC Risk Composer
                </span>
                <span className="text-xs text-blue-200/80 font-medium">
                  Threat Model-as-Code Engine
                </span>
              </div>
            </div>
          </div>

          {/* Center: Abstract Architecture & Value Illustration */}
          <div className="my-10 relative z-10">
            <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/15 shadow-2xl mb-8">
              <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-4">
                <div className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-xs font-mono text-blue-100 uppercase tracking-wider font-semibold">
                    Multi-Developer Workspace
                  </span>
                </div>
                <span className="text-[11px] bg-white/15 px-2 py-0.5 rounded text-blue-100 font-mono">
                  v1.0.0 Pro
                </span>
              </div>

              {/* Architecture Nodes Schematic */}
              <div className="grid grid-cols-3 gap-2.5 my-4">
                <div className="bg-white/10 rounded-lg p-2.5 border border-white/10 text-center">
                  <Cpu className="h-5 w-5 text-blue-200 mx-auto mb-1" />
                  <span className="text-[10px] font-mono text-blue-100 block">IaC Parser</span>
                </div>
                <div className="bg-white/10 rounded-lg p-2.5 border border-white/10 text-center">
                  <Layers className="h-5 w-5 text-emerald-300 mx-auto mb-1" />
                  <span className="text-[10px] font-mono text-blue-100 block">Infra Graph</span>
                </div>
                <div className="bg-white/10 rounded-lg p-2.5 border border-white/10 text-center">
                  <ShieldAlert className="h-5 w-5 text-rose-300 mx-auto mb-1" />
                  <span className="text-[10px] font-mono text-blue-100 block">STRIDE Scan</span>
                </div>
              </div>

              <p className="text-xs text-blue-100/90 leading-relaxed mt-3">
                Transform infrastructure configurations into proactive threat models with
                evidence-grounded risk scoring and safe code patches.
              </p>
            </div>

            {/* Bullet points */}
            <div className="space-y-3">
              {[
                'Multi-developer workspace isolation & project history',
                'Real-time dependency graph & infrastructure explorer',
                'Deterministic STRIDE threat engine with safe patches',
              ].map((text, i) => (
                <div key={i} className="flex items-center gap-2.5 text-xs text-blue-100">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400 flex-shrink-0" />
                  <span>{text}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Footer note */}
          <div className="relative z-10 pt-4 border-t border-white/10 flex items-center justify-between text-[11px] text-blue-200/80">
            <span>Enterprise Security Platform</span>
            <span>Zero Plaintext Passwords</span>
          </div>
        </div>

        {/* Right Side: Sign In Form */}
        <div className="lg:w-1/2 p-8 lg:p-14 flex flex-col justify-center bg-white dark:bg-slate-900 transition-colors">
          <div className="max-w-md w-full mx-auto">
            <div className="mb-8">
              <h1 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">
                Welcome back
              </h1>
              <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                Enter your developer credentials to access your isolated workspace.
              </p>
            </div>

            {error && (
              <div className="mb-5 p-3.5 rounded-lg bg-rose-50 dark:bg-rose-950/50 border border-rose-200 dark:border-rose-900/60 text-rose-700 dark:text-rose-300 text-xs flex items-start gap-2.5 animate-fade-in">
                <ShieldAlert className="h-4 w-4 text-rose-500 flex-shrink-0 mt-0.5" />
                <span className="flex-1">{error}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                  Email or Username
                </label>
                <div className="relative">
                  <User className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={usernameOrEmail}
                    onChange={e => setUsernameOrEmail(e.target.value)}
                    className="input pl-9"
                    placeholder="developer@company.com or username"
                    required
                    autoFocus
                  />
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300">
                    Password
                  </label>
                  <button
                    type="button"
                    onClick={() => setShowForgotModal(true)}
                    className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 hover:underline"
                  >
                    Forgot password?
                  </button>
                </div>
                <div className="relative">
                  <Lock className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="password"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    className="input pl-9"
                    placeholder="••••••••••••"
                    required
                  />
                </div>
              </div>

              <div className="flex items-center justify-between pt-1">
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={rememberMe}
                    onChange={e => setRememberMe(e.target.checked)}
                    className="rounded border-slate-300 dark:border-slate-700 text-blue-600 focus:ring-blue-500 h-4 w-4 dark:bg-slate-800"
                  />
                  <span className="text-xs text-slate-600 dark:text-slate-400 font-medium">Remember this browser</span>
                </label>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="btn-primary w-full py-2.5 text-sm font-semibold shadow mt-2"
              >
                {loading ? 'Authenticating...' : 'Sign In'}
                {!loading && <ArrowRight className="h-4 w-4 ml-1.5" />}
              </button>
            </form>

            {/* Quick Demo Helper */}
            <div className="mt-6 pt-5 border-t border-slate-100 dark:border-slate-800">
              <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-800/60 border border-slate-200/80 dark:border-slate-700/80 rounded-lg p-3">
                <div className="flex items-center gap-2">
                  <Sparkles className="h-4 w-4 text-amber-500" />
                  <span>Demo Admin Account: <code className="font-mono text-slate-700 dark:text-slate-300">admin / admin</code></span>
                </div>
                <button
                  type="button"
                  onClick={handleFillDemo}
                  className="text-blue-600 dark:text-blue-400 font-semibold hover:underline"
                >
                  Auto-fill
                </button>
              </div>
            </div>

            <p className="text-center text-xs text-slate-500 dark:text-slate-400 mt-6">
              Don't have an account yet?{' '}
              <Link to="/register" className="font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 hover:underline">
                Create Developer Account
              </Link>
            </p>
          </div>
        </div>
      </div>

      {/* Forgot Password Modal */}
      {showForgotModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 animate-fade-in">
          <div className="bg-white dark:bg-slate-900 rounded-xl max-w-sm w-full p-6 shadow-xl border border-slate-200 dark:border-slate-800 animate-pop-in">
            <h3 className="text-base font-semibold text-slate-900 dark:text-white mb-2">Reset Password</h3>
            <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed mb-4">
              IaC Risk Composer stores passwords using salted PBKDF2 hashing. In this local deployment, you can update your credentials via the Settings page or use the demo account (<code className="font-mono text-slate-800 dark:text-slate-200">admin / admin</code>).
            </p>
            <button
              onClick={() => setShowForgotModal(false)}
              className="btn-primary w-full text-xs py-2"
            >
              Understood
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
