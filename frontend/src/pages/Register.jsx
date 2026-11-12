/**
 * Register.jsx
 * ------------
 * Multi-developer account creation page.
 * Creates a personal isolated workspace for each developer.
 */

import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  ShieldCheck,
  Lock,
  Mail,
  User,
  Building,
  ArrowRight,
  ShieldAlert,
  CheckCircle2,
} from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { friendlyError } from '../utils/errors'

export default function Register() {
  const { register } = useAuth()
  const navigate = useNavigate()

  const [fullName, setFullName] = useState('')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [organization, setOrganization] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')

    // Client-side validations
    if (password.length < 8) {
      setError('Password must be at least 8 characters long.')
      return
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match.')
      return
    }

    setLoading(true)
    try {
      await register({
        full_name: fullName,
        username,
        email,
        organization: organization || 'Independent Developer',
        password,
        confirm_password: confirmPassword,
      })
      navigate('/dashboard')
    } catch (err) {
      setError(friendlyError(err, 'Failed to create developer account.'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex flex-col justify-center lg:p-6 transition-colors">
      <div className="mx-auto w-full max-w-5xl bg-white dark:bg-slate-900 lg:rounded-2xl lg:shadow-xl lg:border lg:border-slate-200/80 dark:lg:border-slate-800 overflow-hidden flex flex-col lg:flex-row">
        
        {/* Left Side: Value proposition */}
        <div className="lg:w-5/12 bg-gradient-to-br from-blue-700 via-blue-800 to-indigo-900 p-8 lg:p-10 text-white flex flex-col justify-between relative overflow-hidden">
          <div className="relative z-10">
            <div className="flex items-center gap-3 mb-8">
              <div className="h-10 w-10 rounded-xl bg-white/10 backdrop-blur border border-white/20 flex items-center justify-center">
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

            <h2 className="text-2xl font-bold tracking-tight text-white mb-3">
              Join the Multi-Developer Security Platform
            </h2>
            <p className="text-xs text-blue-100/90 leading-relaxed mb-6">
              Create your personal workspace to audit Terraform infrastructure, visualize resource maps, and detect threats before deployment.
            </p>

            <div className="space-y-4 pt-4 border-t border-white/15">
              {[
                {
                  title: 'Private Isolated Workspace',
                  desc: 'Your projects and analyses are stored securely in your private tenant space.',
                },
                {
                  title: 'Persistent Scan History',
                  desc: 'Pick up where you left off whenever you log back into your account.',
                },
                {
                  title: 'Interactive Topology Maps',
                  desc: 'Explore cloud nodes, relationships, and pinpoint vulnerabilities with zero friction.',
                },
              ].map((item, i) => (
                <div key={i} className="flex items-start gap-2.5 text-xs">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <strong className="text-white block font-semibold">{item.title}</strong>
                    <span className="text-blue-100/80">{item.desc}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="relative z-10 pt-6 text-[11px] text-blue-200/80 border-t border-white/10">
            <span>Encrypted credentials with salted PBKDF2</span>
          </div>
        </div>

        {/* Right Side: Registration Form */}
        <div className="lg:w-7/12 p-8 lg:p-12 flex flex-col justify-center bg-white dark:bg-slate-900 transition-colors">
          <div className="max-w-md w-full mx-auto">
            <div className="mb-6">
              <h1 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">
                Create Developer Account
              </h1>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                Set up your personal workspace. No credit card required.
              </p>
            </div>

            {error && (
              <div className="mb-5 p-3.5 rounded-lg bg-rose-50 dark:bg-rose-950/50 border border-rose-200 dark:border-rose-900/60 text-rose-700 dark:text-rose-300 text-xs flex items-start gap-2.5 animate-fade-in">
                <ShieldAlert className="h-4 w-4 text-rose-500 flex-shrink-0 mt-0.5" />
                <span className="flex-1">{error}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-3.5">
              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Full Name <span className="text-rose-500">*</span>
                </label>
                <div className="relative">
                  <User className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={fullName}
                    onChange={e => setFullName(e.target.value)}
                    className="input pl-9 text-xs"
                    placeholder="Alex Morgan"
                    required
                    autoFocus
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Username <span className="text-rose-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    className="input text-xs font-mono"
                    placeholder="alex_dev"
                    required
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Organization / Team (Optional)
                  </label>
                  <div className="relative">
                    <Building className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      value={organization}
                      onChange={e => setOrganization(e.target.value)}
                      className="input pl-9 text-xs"
                      placeholder="Cloud SecOps Team"
                    />
                  </div>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Email Address <span className="text-rose-500">*</span>
                </label>
                <div className="relative">
                  <Mail className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="email"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    className="input pl-9 text-xs"
                    placeholder="alex@company.com"
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Password <span className="text-rose-500">*</span>
                  </label>
                  <div className="relative">
                    <Lock className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="password"
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      className="input pl-9 text-xs"
                      placeholder="Min. 8 characters"
                      required
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Confirm Password <span className="text-rose-500">*</span>
                  </label>
                  <div className="relative">
                    <Lock className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="password"
                      value={confirmPassword}
                      onChange={e => setConfirmPassword(e.target.value)}
                      className="input pl-9 text-xs"
                      placeholder="Repeat password"
                      required
                    />
                  </div>
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="btn-primary w-full py-2.5 text-xs font-semibold shadow mt-4"
              >
                {loading ? 'Creating Workspace...' : 'Create Developer Account'}
                {!loading && <ArrowRight className="h-4 w-4 ml-1.5" />}
              </button>
            </form>

            <p className="text-center text-xs text-slate-500 dark:text-slate-400 mt-6">
              Already have an account?{' '}
              <Link to="/login" className="font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 hover:underline">
                Sign In
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
