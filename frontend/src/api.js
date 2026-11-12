/**
 * api.js
 * -------
 * Thin wrapper around the browser Fetch API.
 * All requests are routed through Vite's /api proxy to http://localhost:8000.
 * Automatically injects the Authorization Bearer token for multi-tenant isolation.
 */

const BASE = '/api'
const TOKEN_KEY = 'iac_auth_token'

export function getAuthToken() {
  return localStorage.getItem(TOKEN_KEY) || sessionStorage.getItem(TOKEN_KEY) || null
}

export function setAuthToken(token, remember = false) {
  if (remember) {
    localStorage.setItem(TOKEN_KEY, token)
    sessionStorage.removeItem(TOKEN_KEY)
  } else {
    sessionStorage.setItem(TOKEN_KEY, token)
    localStorage.removeItem(TOKEN_KEY)
  }
}

export function clearAuthToken() {
  localStorage.removeItem(TOKEN_KEY)
  sessionStorage.removeItem(TOKEN_KEY)
}

async function request(method, path, body) {
  const headers = { 'Content-Type': 'application/json' }
  const token = getAuthToken()
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const opts = { method, headers }
  if (body !== undefined) {
    opts.body = JSON.stringify(body)
  }

  const res = await fetch(`${BASE}${path}`, opts)
  if (!res.ok) {
    let message = `Request failed with status ${res.status}`
    try {
      const data = await res.json()
      if (typeof data.detail === 'string') {
        message = data.detail
      } else if (Array.isArray(data.detail)) {
        message = data.detail.map(d => d.msg || JSON.stringify(d)).join('; ')
      }
    } catch {
      const text = await res.text()
      if (text) message = text
    }
    const err = new Error(message)
    err.status = res.status
    throw err
  }
  return res.json()
}

// ---------------------------------------------------------------------------
// System & Health
// ---------------------------------------------------------------------------

export function getHealth() {
  return request('GET', '/health')
}

// ---------------------------------------------------------------------------
// Authentication & Profile
// ---------------------------------------------------------------------------

export function registerUser(data) {
  return request('POST', '/auth/register', data)
}

export function loginUser(data) {
  return request('POST', '/auth/login', data)
}

export function getCurrentUser() {
  return request('GET', '/auth/me')
}

export function updateUserProfile(data) {
  return request('PUT', '/auth/profile', data)
}

export function changeUserPassword(data) {
  return request('POST', '/auth/change-password', data)
}

export function deleteUserAccount() {
  return request('DELETE', '/auth/account')
}

// ---------------------------------------------------------------------------
// Projects & Workspaces
// ---------------------------------------------------------------------------

export function getProjects() {
  return request('GET', '/projects')
}

export function createProject(data) {
  return request('POST', '/projects', data)
}

export function getProject(projectId) {
  return request('GET', `/projects/${encodeURIComponent(projectId)}`)
}

export function updateProject(projectId, data) {
  return request('PUT', `/projects/${encodeURIComponent(projectId)}`, data)
}

export function deleteProject(projectId) {
  return request('DELETE', `/projects/${encodeURIComponent(projectId)}`)
}

// ---------------------------------------------------------------------------
// Analysis & Scanning
// ---------------------------------------------------------------------------

export async function analyzeTerraformFile(file, projectId = null) {
  const formData = new FormData()
  formData.append('file', file)
  if (projectId) {
    formData.append('project_id', projectId)
  }

  const headers = {}
  const token = getAuthToken()
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const res = await fetch(`${BASE}/analyze`, {
    method: 'POST',
    headers,
    body: formData,
  })

  if (!res.ok) {
    let message = `Request failed with status ${res.status}`
    try {
      const data = await res.json()
      if (typeof data.detail === 'string') {
        message = data.detail
      } else if (Array.isArray(data.detail)) {
        message = data.detail.map(d => d.msg || JSON.stringify(d)).join('; ')
      }
    } catch {
      // response wasn't JSON
    }
    const err = new Error(message)
    err.status = res.status
    throw err
  }

  return res.json()
}

// ---------------------------------------------------------------------------
// Reports & PDF Generation
// ---------------------------------------------------------------------------

export async function downloadSecurityReport(analysisResult) {
  const headers = { 'Content-Type': 'application/json' }
  const token = getAuthToken()
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const res = await fetch(`${BASE}/report`, {
    method: 'POST',
    headers,
    body: JSON.stringify(analysisResult),
  })

  if (!res.ok) {
    let message = `Report generation failed (${res.status})`
    try {
      const data = await res.json()
      if (typeof data.detail === 'string') message = data.detail
    } catch {
      // ignore
    }
    throw new Error(message)
  }

  const blob = await res.blob()
  const url = window.URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url

  const rawFilename = (analysisResult && analysisResult.filename) || 'iac_analysis'
  const safeBase = rawFilename.replace(/[^a-zA-Z0-9_-]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '') || 'iac_analysis'
  a.download = `${safeBase}_security_report.pdf`

  document.body.appendChild(a)
  a.click()
  window.URL.revokeObjectURL(url)
  document.body.removeChild(a)
}

export function getSavedReports(projectId = null) {
  const query = projectId ? `?project_id=${encodeURIComponent(projectId)}` : ''
  return request('GET', `/reports${query}`)
}

export function getSavedReport(reportId) {
  return request('GET', `/reports/${encodeURIComponent(reportId)}`)
}

export async function downloadSavedReportPdf(reportId, filename = 'iac_analysis') {
  const headers = {}
  const token = getAuthToken()
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const res = await fetch(`${BASE}/reports/${encodeURIComponent(reportId)}/pdf`, { headers })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`PDF download failed (${res.status}): ${text}`)
  }

  const blob = await res.blob()
  const url = window.URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url

  const safeBase = filename.replace(/[^a-zA-Z0-9_-]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '') || 'iac_analysis'
  a.download = `${safeBase}_security_report.pdf`

  document.body.appendChild(a)
  a.click()
  window.URL.revokeObjectURL(url)
  document.body.removeChild(a)
}

export function deleteSavedReport(reportId) {
  return request('DELETE', `/reports/${encodeURIComponent(reportId)}`)
}

export function getDashboardStats() {
  return request('GET', '/dashboard/stats')
}
