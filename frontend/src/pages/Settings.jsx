/**
 * Settings.jsx
 * ------------
 * Professional application settings for developers:
 * - Profile: Full Name, Email, Username, Organization, Avatar, Change Password
 * - Appearance: Real-time Light / Dark / System theme switching with accessibility
 * - Notifications: Security alerts, Analysis completed, Critical alerts
 * - Analysis Preferences: Severity thresholds, patch generation, graph auto-layout
 * - Account: Session info, Sign out, Delete Account danger zone
 */

import React, { useState, useEffect } from 'react'
import {
  User,
  Shield,
  KeyRound,
  Palette,
  Bell,
  Sliders,
  AlertTriangle,
  LogOut,
  Trash2,
  CheckCircle2,
  Loader2,
  Building,
  Mail,
  AtSign,
  Sun,
  Moon,
  Laptop,
} from 'lucide-react'
import PageHeader from '../components/common/PageHeader'
import { useAuth } from '../context/AuthContext'
import { useTheme } from '../context/ThemeContext'

export default function Settings() {
  const { user, updateProfile, changePassword, logout, deleteAccount } = useAuth()
  const { theme, resolvedTheme, setTheme } = useTheme()

  // Tabs: 'profile' | 'appearance' | 'notifications' | 'analysis' | 'account'
  const [activeTab, setActiveTab] = useState('appearance') // Default to appearance so user lands right on what they want

  // Profile form state
  const [fullName, setFullName] = useState(user?.full_name || '')
  const [organization, setOrganization] = useState(user?.organization || '')
  const [profileSaving, setProfileSaving] = useState(false)
  const [profileMessage, setProfileMessage] = useState(null)
  const [profileError, setProfileError] = useState(null)

  // Password change state
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordSaving, setPasswordSaving] = useState(false)
  const [passwordMessage, setPasswordMessage] = useState(null)
  const [passwordError, setPasswordError] = useState(null)

  // Theme notice
  const [themeNotice, setThemeNotice] = useState(null)

  // Notifications state
  const [notifyCritical, setNotifyCritical] = useState(
    user?.preferences?.notify_critical !== false
  )
  const [notifyAnalysisComplete, setNotifyAnalysisComplete] = useState(
    user?.preferences?.notify_analysis_complete !== false
  )
  const [notifyDigest, setNotifyDigest] = useState(
    user?.preferences?.notify_digest || false
  )
  const [notifySaving, setNotifySaving] = useState(false)
  const [notifyNotice, setNotifyNotice] = useState(false)

  // Analysis preferences
  const [minSeverity, setMinSeverity] = useState(
    user?.preferences?.min_severity || 'low'
  )
  const [generatePatches, setGeneratePatches] = useState(
    user?.preferences?.generate_patches !== false
  )
  const [autoMapGraph, setAutoMapGraph] = useState(
    user?.preferences?.auto_map_graph !== false
  )
  const [analysisPrefsSaving, setAnalysisPrefsSaving] = useState(false)
  const [analysisPrefsNotice, setAnalysisPrefsNotice] = useState(false)

  // Account danger zone
  const [confirmDeleteOpen, setConfirmDeleteOpen] = useState(false)
  const [deleteInput, setDeleteInput] = useState('')
  const [deleteError, setDeleteError] = useState(null)
  const [isDeleting, setIsDeleting] = useState(false)

  // Sync state if user changes
  useEffect(() => {
    if (user?.full_name) setFullName(user.full_name)
    if (user?.organization) setOrganization(user.organization)
  }, [user])

  // Handlers
  async function handleProfileSave(e) {
    e.preventDefault()
    setProfileSaving(true)
    setProfileMessage(null)
    setProfileError(null)

    try {
      await updateProfile({
        full_name: fullName.trim(),
        organization: organization.trim() || null,
      })
      setProfileMessage('Profile details updated successfully.')
      setTimeout(() => setProfileMessage(null), 4000)
    } catch (err) {
      setProfileError(err.message || 'Failed to update profile.')
    } finally {
      setProfileSaving(false)
    }
  }

  async function handlePasswordChange(e) {
    e.preventDefault()
    setPasswordSaving(true)
    setPasswordMessage(null)
    setPasswordError(null)

    if (newPassword.length < 8) {
      setPasswordError('New password must be at least 8 characters long.')
      setPasswordSaving(false)
      return
    }

    if (newPassword !== confirmPassword) {
      setPasswordError('New passwords do not match.')
      setPasswordSaving(false)
      return
    }

    try {
      await changePassword(currentPassword, newPassword, confirmPassword)
      setPasswordMessage('Password changed successfully.')
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      setTimeout(() => setPasswordMessage(null), 4000)
    } catch (err) {
      setPasswordError(err.message || 'Failed to change password.')
    } finally {
      setPasswordSaving(false)
    }
  }

  function handleThemeChange(newTheme) {
    // 1. Immediately toggle the active theme via ThemeContext (applies .dark class to root)
    setTheme(newTheme)
    const label = newTheme === 'system' ? 'System Sync' : newTheme === 'dark' ? 'Dark Theme' : 'Light Theme'
    setThemeNotice(`Applied ${label} successfully.`)
    setTimeout(() => setThemeNotice(null), 3500)

    // 2. Persist in developer profile preferences on backend
    if (user && updateProfile) {
      updateProfile({
        preferences: {
          ...(user?.preferences || {}),
          theme: newTheme,
        },
      }).catch(err => {
        console.warn('Backend preference sync failed:', err)
      })
    }
  }

  async function handleNotificationSave() {
    setNotifySaving(true)
    try {
      await updateProfile({
        preferences: {
          ...(user?.preferences || {}),
          notify_critical: notifyCritical,
          notify_analysis_complete: notifyAnalysisComplete,
          notify_digest: notifyDigest,
        },
      })
      setNotifyNotice(true)
      setTimeout(() => setNotifyNotice(false), 3000)
    } catch (err) {
      console.error('Failed to save notification preferences:', err)
    } finally {
      setNotifySaving(false)
    }
  }

  async function handleAnalysisPrefsSave() {
    setAnalysisPrefsSaving(true)
    try {
      await updateProfile({
        preferences: {
          ...(user?.preferences || {}),
          min_severity: minSeverity,
          generate_patches: generatePatches,
          auto_map_graph: autoMapGraph,
        },
      })
      setAnalysisPrefsNotice(true)
      setTimeout(() => setAnalysisPrefsNotice(false), 3000)
    } catch (err) {
      console.error('Failed to save analysis preferences:', err)
    } finally {
      setAnalysisPrefsSaving(false)
    }
  }

  async function handleDeleteAccount() {
    if (deleteInput !== user?.username) {
      setDeleteError(`Please type your exact username "${user?.username}" to confirm.`)
      return
    }

    setIsDeleting(true)
    setDeleteError(null)
    try {
      await deleteAccount()
    } catch (err) {
      setDeleteError(err.message || 'Failed to delete account.')
      setIsDeleting(false)
    }
  }

  const tabs = [
    { id: 'appearance', label: 'Appearance', icon: Palette },
    { id: 'profile', label: 'Profile & Security', icon: User },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'analysis', label: 'Analysis Preferences', icon: Sliders },
    { id: 'account', label: 'Account & Workspace', icon: Shield },
  ]

  // User Initials
  const initials = (user?.full_name || user?.username || 'DV')
    .split(' ')
    .filter(Boolean)
    .slice(0, 2)
    .map(p => p[0].toUpperCase())
    .join('')

  return (
    <div className="space-y-6 max-w-5xl">
      <PageHeader
        title="Settings"
        description="Manage your developer profile, appearance, workspace notifications, and account credentials."
      />

      <div className="flex flex-col md:flex-row gap-6 items-start">
        {/* Settings Navigation Sidebar */}
        <aside className="w-full md:w-64 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-2 shadow-xs shrink-0 transition-colors duration-200">
          <div className="p-3 mb-2 flex items-center gap-3 border-b border-slate-100 dark:border-slate-800">
            <div className="w-10 h-10 rounded-full bg-blue-100 dark:bg-blue-950 border border-blue-200 dark:border-blue-800 text-blue-700 dark:text-blue-300 font-bold flex items-center justify-center text-sm shadow-xs">
              {initials}
            </div>
            <div className="min-w-0">
              <p className="text-sm font-semibold text-slate-900 dark:text-slate-100 truncate">
                {user?.full_name || user?.username}
              </p>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-mono truncate">@{user?.username}</p>
            </div>
          </div>

          <nav className="space-y-1">
            {tabs.map(tab => {
              const Icon = tab.icon
              const active = activeTab === tab.id
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`w-full flex items-center gap-2.5 px-3 py-2 text-sm font-medium rounded-lg transition-colors text-left ${
                    active
                      ? 'bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 font-semibold shadow-xs border border-transparent dark:border-blue-800/50'
                      : 'text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${active ? 'text-blue-600 dark:text-blue-400' : 'text-slate-400 dark:text-slate-500'}`} />
                  <span>{tab.label}</span>
                </button>
              )
            })}
          </nav>
        </aside>

        {/* Tab Content Panes */}
        <div className="flex-1 w-full space-y-6">
          {/* TAB: APPEARANCE */}
          {activeTab === 'appearance' && (
            <div className="card space-y-6">
              <div>
                <h3 className="section-title">Interface Appearance</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  Select your theme preference. Both high-contrast Light Theme and modern Dark Theme are fully supported across all charts, graphs, and security finding details.
                </p>
              </div>

              {themeNotice && (
                <div className="flex items-center gap-2 px-3 py-2.5 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 rounded-lg text-xs text-emerald-800 dark:text-emerald-300 font-medium animate-fade-in">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                  <span>{themeNotice}</span>
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                {/* 1. Light Theme */}
                <button
                  type="button"
                  onClick={() => handleThemeChange('light')}
                  className={`p-4 rounded-xl border text-left transition-all relative ${
                    theme === 'light'
                      ? 'border-blue-600 ring-2 ring-blue-500/20 bg-blue-50/40 dark:bg-blue-950/30 dark:border-blue-500'
                      : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 bg-white dark:bg-slate-900'
                  }`}
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="w-10 h-10 rounded-xl bg-amber-50 dark:bg-amber-950/60 border border-amber-200 dark:border-amber-800/80 text-amber-600 dark:text-amber-400 flex items-center justify-center shadow-xs">
                      <Sun className="w-5 h-5" />
                    </div>
                    {theme === 'light' && (
                      <span className="text-[10px] font-bold uppercase tracking-wider bg-blue-100 dark:bg-blue-900/80 text-blue-700 dark:text-blue-300 px-2 py-0.5 rounded-full">
                        Active
                      </span>
                    )}
                  </div>
                  <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100">Light Theme</h4>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
                    Crisp white surfaces, slate borders, and high-visibility risk markers for daytime reviews.
                  </p>
                </button>

                {/* 2. Dark Theme */}
                <button
                  type="button"
                  onClick={() => handleThemeChange('dark')}
                  className={`p-4 rounded-xl border text-left transition-all relative ${
                    theme === 'dark'
                      ? 'border-blue-600 ring-2 ring-blue-500/20 bg-blue-50/40 dark:bg-blue-950/30 dark:border-blue-500'
                      : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 bg-white dark:bg-slate-900'
                  }`}
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="w-10 h-10 rounded-xl bg-slate-800 dark:bg-slate-800 border border-slate-700 text-blue-400 flex items-center justify-center shadow-xs">
                      <Moon className="w-5 h-5" />
                    </div>
                    {theme === 'dark' && (
                      <span className="text-[10px] font-bold uppercase tracking-wider bg-blue-100 dark:bg-blue-900/80 text-blue-700 dark:text-blue-300 px-2 py-0.5 rounded-full">
                        Active
                      </span>
                    )}
                  </div>
                  <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100">Dark Theme</h4>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
                    Deep charcoal slate surfaces and high-contrast glowing indicators for reduced eye strain.
                  </p>
                </button>

                {/* 3. System Theme */}
                <button
                  type="button"
                  onClick={() => handleThemeChange('system')}
                  className={`p-4 rounded-xl border text-left transition-all relative ${
                    theme === 'system'
                      ? 'border-blue-600 ring-2 ring-blue-500/20 bg-blue-50/40 dark:bg-blue-950/30 dark:border-blue-500'
                      : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 bg-white dark:bg-slate-900'
                  }`}
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="w-10 h-10 rounded-xl bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 flex items-center justify-center shadow-xs">
                      <Laptop className="w-5 h-5" />
                    </div>
                    {theme === 'system' && (
                      <span className="text-[10px] font-bold uppercase tracking-wider bg-blue-100 dark:bg-blue-900/80 text-blue-700 dark:text-blue-300 px-2 py-0.5 rounded-full">
                        Active
                      </span>
                    )}
                  </div>
                  <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100">System Sync</h4>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
                    Automatically match your operating system's light or dark appearance setting.
                  </p>
                  {theme === 'system' && (
                    <div className="mt-2 text-[10px] font-semibold text-blue-600 dark:text-blue-400">
                      OS currently resolving: {resolvedTheme === 'dark' ? 'Dark Mode' : 'Light Mode'}
                    </div>
                  )}
                </button>
              </div>

              {/* Theme status summary */}
              <div className="inset-box p-3.5 flex items-center justify-between text-xs">
                <span className="text-slate-600 dark:text-slate-400">
                  Current Display State: <strong className="text-slate-900 dark:text-slate-100 capitalize">{resolvedTheme} Mode</strong>
                  {theme === 'system' && <span className="text-slate-400 dark:text-slate-500 ml-1">(Synced to OS)</span>}
                </span>
                <span className="text-[11px] text-slate-500 dark:text-slate-400">
                  You can also toggle themes anytime from the sun/moon icon in the top navigation bar.
                </span>
              </div>
            </div>
          )}

          {/* TAB: PROFILE & SECURITY */}
          {activeTab === 'profile' && (
            <>
              {/* Profile Details Card */}
              <div className="card space-y-6">
                <div>
                  <h3 className="section-title">Developer Profile</h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Your personal identification and organization details within your workspace.
                  </p>
                </div>

                {profileMessage && (
                  <div className="flex items-center gap-2 px-3 py-2.5 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 rounded-lg text-xs text-emerald-800 dark:text-emerald-300 font-medium">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                    <span>{profileMessage}</span>
                  </div>
                )}

                {profileError && (
                  <div className="flex items-center gap-2 px-3 py-2.5 bg-rose-50 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800 rounded-lg text-xs text-rose-800 dark:text-rose-300 font-medium">
                    <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0" />
                    <span>{profileError}</span>
                  </div>
                )}

                <form onSubmit={handleProfileSave} className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                        Full Name
                      </label>
                      <input
                        type="text"
                        value={fullName}
                        onChange={e => setFullName(e.target.value)}
                        required
                        className="input"
                        placeholder="e.g. Alex Chen"
                      />
                    </div>

                    <div>
                      <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                        Organization / Team
                      </label>
                      <div className="relative">
                        <Building className="w-4 h-4 text-slate-400 dark:text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                        <input
                          type="text"
                          value={organization}
                          onChange={e => setOrganization(e.target.value)}
                          className="input pl-9"
                          placeholder="e.g. Acme Cloud Security"
                        />
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                        Username
                      </label>
                      <div className="relative">
                        <AtSign className="w-4 h-4 text-slate-400 dark:text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                        <input
                          type="text"
                          value={user?.username || ''}
                          disabled
                          className="input pl-9 bg-slate-50 dark:bg-slate-950/50 text-slate-500 dark:text-slate-400 cursor-not-allowed"
                        />
                      </div>
                      <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Username cannot be changed after account creation.</p>
                    </div>

                    <div>
                      <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                        Email Address
                      </label>
                      <div className="relative">
                        <Mail className="w-4 h-4 text-slate-400 dark:text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                        <input
                          type="email"
                          value={user?.email || ''}
                          disabled
                          className="input pl-9 bg-slate-50 dark:bg-slate-950/50 text-slate-500 dark:text-slate-400 cursor-not-allowed"
                        />
                      </div>
                      <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-1">Used for login, session recovery, and alert dispatches.</p>
                    </div>
                  </div>

                  <div className="flex justify-end pt-2">
                    <button
                      type="submit"
                      disabled={profileSaving}
                      className="btn-primary"
                    >
                      {profileSaving ? (
                        <>
                          <Loader2 className="w-4 h-4 animate-spin" />
                          <span>Saving…</span>
                        </>
                      ) : (
                        'Save Profile Changes'
                      )}
                    </button>
                  </div>
                </form>
              </div>

              {/* Change Password Card */}
              <div className="card space-y-6">
                <div>
                  <h3 className="section-title flex items-center gap-2">
                    <KeyRound className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                    <span>Change Password</span>
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Update your account password. Use at least 8 characters with a mix of letters and numbers.
                  </p>
                </div>

                {passwordMessage && (
                  <div className="flex items-center gap-2 px-3 py-2.5 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 rounded-lg text-xs text-emerald-800 dark:text-emerald-300 font-medium">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                    <span>{passwordMessage}</span>
                  </div>
                )}

                {passwordError && (
                  <div className="flex items-center gap-2 px-3 py-2.5 bg-rose-50 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800 rounded-lg text-xs text-rose-800 dark:text-rose-300 font-medium">
                    <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0" />
                    <span>{passwordError}</span>
                  </div>
                )}

                <form onSubmit={handlePasswordChange} className="space-y-4 max-w-lg">
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                      Current Password
                    </label>
                    <input
                      type="password"
                      value={currentPassword}
                      onChange={e => setCurrentPassword(e.target.value)}
                      required
                      className="input"
                      placeholder="••••••••"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                      New Password
                    </label>
                    <input
                      type="password"
                      value={newPassword}
                      onChange={e => setNewPassword(e.target.value)}
                      required
                      minLength={8}
                      className="input"
                      placeholder="At least 8 characters"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                      Confirm New Password
                    </label>
                    <input
                      type="password"
                      value={confirmPassword}
                      onChange={e => setConfirmPassword(e.target.value)}
                      required
                      minLength={8}
                      className="input"
                      placeholder="Re-enter new password"
                    />
                  </div>

                  <div className="pt-2">
                    <button
                      type="submit"
                      disabled={passwordSaving || !currentPassword || !newPassword}
                      className="btn-primary"
                    >
                      {passwordSaving ? (
                        <>
                          <Loader2 className="w-4 h-4 animate-spin" />
                          <span>Updating…</span>
                        </>
                      ) : (
                        'Update Password'
                      )}
                    </button>
                  </div>
                </form>
              </div>
            </>
          )}

          {/* TAB: NOTIFICATIONS */}
          {activeTab === 'notifications' && (
            <div className="card space-y-6">
              <div>
                <h3 className="section-title">Notification Settings</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  Configure real-time alerts and scan completion notifications.
                </p>
              </div>

              {notifyNotice && (
                <div className="flex items-center gap-2 px-3 py-2 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 rounded-lg text-xs text-emerald-800 dark:text-emerald-300 font-medium">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                  <span>Notification preferences saved.</span>
                </div>
              )}

              <div className="space-y-4">
                <label className="flex items-start justify-between gap-4 p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 hover:bg-slate-50/50 dark:hover:bg-slate-800/50 cursor-pointer transition-colors">
                  <div>
                    <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">Critical Threat Alerts</p>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                      Receive immediate alerts whenever an analysis detects critical risk severity findings (e.g. public S3 buckets, unrestricted 0.0.0.0/0 ingress).
                    </p>
                  </div>
                  <input
                    type="checkbox"
                    checked={notifyCritical}
                    onChange={e => setNotifyCritical(e.target.checked)}
                    className="w-4 h-4 text-blue-600 rounded border-slate-300 dark:border-slate-700 focus:ring-blue-500 mt-1"
                  />
                </label>

                <label className="flex items-start justify-between gap-4 p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 hover:bg-slate-50/50 dark:hover:bg-slate-800/50 cursor-pointer transition-colors">
                  <div>
                    <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">Analysis Completion Notifications</p>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                      Display banner alerts and update top bar indicators when background IaC pipeline scans finish processing.
                    </p>
                  </div>
                  <input
                    type="checkbox"
                    checked={notifyAnalysisComplete}
                    onChange={e => setNotifyAnalysisComplete(e.target.checked)}
                    className="w-4 h-4 text-blue-600 rounded border-slate-300 dark:border-slate-700 focus:ring-blue-500 mt-1"
                  />
                </label>

                <label className="flex items-start justify-between gap-4 p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 hover:bg-slate-50/50 dark:hover:bg-slate-800/50 cursor-pointer transition-colors">
                  <div>
                    <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">Weekly Security Posture Summary</p>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                      Receive an executive summary of risk trends and resolved vulnerabilities across your active projects.
                    </p>
                  </div>
                  <input
                    type="checkbox"
                    checked={notifyDigest}
                    onChange={e => setNotifyDigest(e.target.checked)}
                    className="w-4 h-4 text-blue-600 rounded border-slate-300 dark:border-slate-700 focus:ring-blue-500 mt-1"
                  />
                </label>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  type="button"
                  onClick={handleNotificationSave}
                  disabled={notifySaving}
                  className="btn-primary"
                >
                  {notifySaving ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>Saving…</span>
                    </>
                  ) : (
                    'Save Notification Preferences'
                  )}
                </button>
              </div>
            </div>
          )}

          {/* TAB: ANALYSIS PREFERENCES */}
          {activeTab === 'analysis' && (
            <div className="card space-y-6">
              <div>
                <h3 className="section-title">Analysis Preferences</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  Tune how IaC Risk Composer parses, maps, and generates remediations for your configurations.
                </p>
              </div>

              {analysisPrefsNotice && (
                <div className="flex items-center gap-2 px-3 py-2 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 rounded-lg text-xs text-emerald-800 dark:text-emerald-300 font-medium">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                  <span>Analysis preferences saved.</span>
                </div>
              )}

              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                    Default Severity Filter Threshold
                  </label>
                  <select
                    value={minSeverity}
                    onChange={e => setMinSeverity(e.target.value)}
                    className="input max-w-sm"
                  >
                    <option value="low">All Findings (Low, Medium, High, Critical)</option>
                    <option value="medium">Medium, High & Critical (Recommended for production)</option>
                    <option value="high">High & Critical Only (Zero-noise mode)</option>
                    <option value="critical">Critical Only</option>
                  </select>
                  <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-1">
                    Controls the default threat list filter when opening a newly completed scan.
                  </p>
                </div>

                <div className="pt-2 border-t border-slate-100 dark:border-slate-800 space-y-3">
                  <label className="flex items-start justify-between gap-4 p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 hover:bg-slate-50/50 dark:hover:bg-slate-800/50 cursor-pointer transition-colors">
                    <div>
                      <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">Auto-Generate Safe Remediation Code Patches</p>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                        Automatically synthesize clean HCL/YAML remediation snippets showing the exact replacement diff to fix each threat.
                      </p>
                    </div>
                    <input
                      type="checkbox"
                      checked={generatePatches}
                      onChange={e => setGeneratePatches(e.target.checked)}
                      className="w-4 h-4 text-blue-600 rounded border-slate-300 dark:border-slate-700 focus:ring-blue-500 mt-1"
                    />
                  </label>

                  <label className="flex items-start justify-between gap-4 p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 hover:bg-slate-50/50 dark:hover:bg-slate-800/50 cursor-pointer transition-colors">
                    <div>
                      <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">Auto-Generate Infrastructure Architecture Map</p>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                        Build interactive React Flow node graph diagrams with resource risk color-coding immediately upon parsing.
                      </p>
                    </div>
                    <input
                      type="checkbox"
                      checked={autoMapGraph}
                      onChange={e => setAutoMapGraph(e.target.checked)}
                      className="w-4 h-4 text-blue-600 rounded border-slate-300 dark:border-slate-700 focus:ring-blue-500 mt-1"
                    />
                  </label>
                </div>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  type="button"
                  onClick={handleAnalysisPrefsSave}
                  disabled={analysisPrefsSaving}
                  className="btn-primary"
                >
                  {analysisPrefsSaving ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>Saving…</span>
                    </>
                  ) : (
                    'Save Analysis Preferences'
                  )}
                </button>
              </div>
            </div>
          )}

          {/* TAB: ACCOUNT & WORKSPACE */}
          {activeTab === 'account' && (
            <div className="space-y-6">
              {/* Account Overview */}
              <div className="card space-y-4">
                <h3 className="section-title">Session & Workspace Security</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Your developer account is secured with PBKDF2-HMAC-SHA256 password derivation and authenticated session bearer tokens.
                </p>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                  <div className="inset-box p-3 space-y-1">
                    <p className="text-slate-500 dark:text-slate-400 font-medium">Developer ID</p>
                    <p className="font-mono text-slate-800 dark:text-slate-200 font-semibold">{user?.id}</p>
                  </div>
                  <div className="inset-box p-3 space-y-1">
                    <p className="text-slate-500 dark:text-slate-400 font-medium">Account Created</p>
                    <p className="text-slate-800 dark:text-slate-200 font-semibold">
                      {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'Active'}
                    </p>
                  </div>
                </div>

                <div className="pt-2 flex justify-start">
                  <button
                    type="button"
                    onClick={logout}
                    className="btn-ghost text-slate-700 dark:text-slate-200 hover:text-slate-900 dark:hover:text-white border border-slate-200 dark:border-slate-700"
                  >
                    <LogOut className="w-4 h-4" />
                    <span>Sign Out of IaC Risk Composer</span>
                  </button>
                </div>
              </div>

              {/* Danger Zone */}
              <div className="border border-rose-200 dark:border-rose-900/50 rounded-xl bg-rose-50/40 dark:bg-rose-950/20 p-6 space-y-4">
                <div className="flex items-center gap-2 text-rose-700 dark:text-rose-400">
                  <AlertTriangle className="w-5 h-5 shrink-0" />
                  <h3 className="text-base font-semibold">Danger Zone</h3>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                  Permanently delete your developer account and remove all personal projects, analyses, threat records, and reports.
                  This action cannot be undone. Other developers' workspaces will not be affected.
                </p>

                <button
                  type="button"
                  onClick={() => setConfirmDeleteOpen(true)}
                  className="btn-danger"
                >
                  <Trash2 className="w-4 h-4" />
                  <span>Delete Developer Account</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Account Deletion Confirmation Modal */}
      {confirmDeleteOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-900 rounded-2xl max-w-md w-full p-6 shadow-2xl border border-slate-200 dark:border-slate-800 space-y-4">
            <div className="flex items-center gap-3 text-rose-600 dark:text-rose-400">
              <div className="w-10 h-10 rounded-full bg-rose-100 dark:bg-rose-950 flex items-center justify-center shrink-0">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">Delete Account Permanently</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">This action is irreversible.</p>
              </div>
            </div>

            <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
              All your projects, uploaded infrastructure files, identified threats, and historical reports will be permanently purged from the database.
            </p>

            {deleteError && (
              <p className="text-xs text-rose-600 dark:text-rose-300 font-medium bg-rose-50 dark:bg-rose-950/60 p-2.5 rounded-lg border border-rose-200 dark:border-rose-800">
                {deleteError}
              </p>
            )}

            <div className="space-y-1.5">
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300">
                Type your username <span className="font-mono text-rose-600 dark:text-rose-400">{user?.username}</span> to confirm:
              </label>
              <input
                type="text"
                value={deleteInput}
                onChange={e => setDeleteInput(e.target.value)}
                placeholder={user?.username}
                className="input"
              />
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => {
                  setConfirmDeleteOpen(false)
                  setDeleteInput('')
                  setDeleteError(null)
                }}
                disabled={isDeleting}
                className="btn-ghost"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDeleteAccount}
                disabled={isDeleting || deleteInput !== user?.username}
                className="btn-danger"
              >
                {isDeleting ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Deleting…</span>
                  </>
                ) : (
                  'Permanently Delete Account'
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
