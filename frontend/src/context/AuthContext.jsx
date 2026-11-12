/**
 * AuthContext.jsx
 * ----------------
 * Real multi-developer authentication state management in React context.
 * Connects directly to backend /api/auth endpoints with PBKDF2/HMAC-SHA256 tokens.
 * Automatically restores returning developers' sessions from storage.
 */

import React, { createContext, useContext, useEffect, useState } from 'react'
import {
  changeUserPassword,
  clearAuthToken,
  deleteUserAccount,
  getAuthToken,
  getCurrentUser,
  loginUser,
  registerUser,
  setAuthToken,
  updateUserProfile,
} from '../api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [token, setToken] = useState(() => getAuthToken())
  const [loading, setLoading] = useState(true)

  // Verify and hydrate current developer on app boot / refresh
  useEffect(() => {
    let cancelled = false
    async function initAuth() {
      const storedToken = getAuthToken()
      if (!storedToken) {
        if (!cancelled) setLoading(false)
        return
      }

      try {
        const profile = await getCurrentUser()
        if (!cancelled) {
          setUser(profile)
          setToken(storedToken)
        }
      } catch (err) {
        console.warn('Session verification failed, resetting token:', err)
        clearAuthToken()
        if (!cancelled) {
          setUser(null)
          setToken(null)
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    initAuth()
    return () => {
      cancelled = true
    }
  }, [])

  /** Developer sign in */
  async function login(usernameOrEmail, password, rememberMe = false) {
    const data = await loginUser({
      username_or_email: usernameOrEmail,
      password,
      remember_me: rememberMe,
    })
    setAuthToken(data.token, rememberMe)
    setToken(data.token)
    setUser(data.user)
    return data.user
  }

  /** Developer registration */
  async function register(registrationData) {
    const data = await registerUser(registrationData)
    setAuthToken(data.token, true)
    setToken(data.token)
    setUser(data.user)
    return data.user
  }

  /** Sign out */
  function logout() {
    clearAuthToken()
    setToken(null)
    setUser(null)
  }

  /** Update profile or application preferences */
  async function updateProfile(data) {
    const updated = await updateUserProfile(data)
    setUser(updated)
    return updated
  }

  /** Change developer password */
  async function changePassword(currentPassword, newPassword, confirmPassword) {
    return changeUserPassword({
      current_password: currentPassword,
      new_password: newPassword,
      confirm_password: confirmPassword,
    })
  }

  /** Delete account */
  async function deleteAccount() {
    await deleteUserAccount()
    logout()
  }

  const value = {
    user,
    token,
    loading,
    isAuthenticated: !!user,
    login,
    register,
    logout,
    updateProfile,
    changePassword,
    deleteAccount,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

/** Convenience hook – throws if used outside <AuthProvider>. */
export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
