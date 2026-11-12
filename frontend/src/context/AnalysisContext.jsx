/**
 * AnalysisContext.jsx
 * --------------------
 * Shares the active workspace project and current analysis across Dashboard,
 * Infrastructure Map, Threats, and IaC Analysis.
 *
 * Automatically retrieves returning developers' projects and previous work
 * so they are never presented with an empty dashboard if they have past scans.
 */

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { getProjects, getSavedReport, getSavedReports } from '../api'
import { safeStorage } from '../utils/storage'
import { friendlyError } from '../utils/errors'

const ANALYSIS_STORAGE_KEY = 'current_analysis_id'
const PROJECT_STORAGE_KEY = 'current_project_id'

const AnalysisContext = createContext(null)

export function AnalysisProvider({ children }) {
  const [currentId, setCurrentIdState] = useState(() =>
    safeStorage.get(ANALYSIS_STORAGE_KEY, null, 'sessionStorage')
  )
  const [currentProjectId, setCurrentProjectIdState] = useState(() =>
    safeStorage.get(PROJECT_STORAGE_KEY, null, 'sessionStorage')
  )
  const [projects, setProjects] = useState([])
  const [result, setResult] = useState(null)
  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const setCurrentId = useCallback((id) => {
    setCurrentIdState(id)
    if (id) safeStorage.set(ANALYSIS_STORAGE_KEY, id, 'sessionStorage')
    else safeStorage.remove(ANALYSIS_STORAGE_KEY, 'sessionStorage')
  }, [])

  const setCurrentProjectId = useCallback((projId) => {
    setCurrentProjectIdState(projId)
    if (projId) safeStorage.set(PROJECT_STORAGE_KEY, projId, 'sessionStorage')
    else safeStorage.remove(PROJECT_STORAGE_KEY, 'sessionStorage')
  }, [])

  const refreshProjects = useCallback(async () => {
    try {
      const list = await getProjects()
      const projs = Array.isArray(list) ? list : []
      setProjects(projs)
      return projs
    } catch {
      return []
    }
  }, [])

  const refreshReportList = useCallback(async (projId = null) => {
    try {
      const list = await getSavedReports(projId)
      const reps = Array.isArray(list) ? list : []
      setReports(reps)
      return reps
    } catch {
      return []
    }
  }, [])

  const loadResult = useCallback(async (id) => {
    if (!id) {
      setResult(null)
      return
    }
    setLoading(true)
    setError('')
    try {
      const data = await getSavedReport(id)
      setResult(data)
      setCurrentId(data.id || id)
      if (data.project_id) {
        setCurrentProjectId(data.project_id)
      }
    } catch (err) {
      setError(friendlyError(err, 'Unable to load that analysis result.'))
      setResult(null)
    } finally {
      setLoading(false)
    }
  }, [setCurrentId, setCurrentProjectId])

  // Initial resolution on boot / returning developer login:
  // 1. Fetch developer's projects
  // 2. Fetch developer's saved reports
  // 3. Select remembered analysis or most recent analysis
  useEffect(() => {
    let cancelled = false
    async function init() {
      setLoading(true)
      try {
        const [projs, reps] = await Promise.all([
          refreshProjects(),
          refreshReportList(currentProjectId),
        ])
        if (cancelled) return

        // Set default project if not set
        if (!currentProjectId && projs.length > 0) {
          setCurrentProjectId(projs[0].id)
        }

        // Determine analysis to display
        const targetId = currentId || reps[0]?.id
        if (targetId) {
          await loadResult(targetId)
        } else {
          setLoading(false)
        }
      } catch {
        if (!cancelled) setLoading(false)
      }
    }

    init()
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const setResultDirectly = useCallback((data) => {
    setResult(data)
    if (data?.id) setCurrentId(data.id)
    if (data?.project_id) setCurrentProjectId(data.project_id)
    refreshReportList(data?.project_id || null)
    refreshProjects()
  }, [setCurrentId, setCurrentProjectId, refreshReportList, refreshProjects])

  const selectProject = useCallback(async (projId) => {
    setCurrentProjectId(projId)
    const reps = await refreshReportList(projId)
    if (reps.length > 0) {
      await loadResult(reps[0].id)
    } else {
      setResult(null)
      setCurrentId(null)
    }
  }, [setCurrentProjectId, refreshReportList, loadResult, setCurrentId])

  const currentProject = useMemo(() => {
    return projects.find(p => p.id === currentProjectId) || projects[0] || null
  }, [projects, currentProjectId])

  const value = useMemo(() => ({
    result,
    reports,
    projects,
    currentProject,
    currentProjectId,
    currentId,
    loading,
    error,
    selectReport: loadResult,
    selectProject,
    setResult: setResultDirectly,
    refreshReportList,
    refreshProjects,
    hasAnyReports: reports.length > 0,
    hasAnyProjects: projects.length > 0,
  }), [
    result,
    reports,
    projects,
    currentProject,
    currentProjectId,
    currentId,
    loading,
    error,
    loadResult,
    selectProject,
    setResultDirectly,
    refreshReportList,
    refreshProjects,
  ])

  return <AnalysisContext.Provider value={value}>{children}</AnalysisContext.Provider>
}

export function useAnalysis() {
  const ctx = useContext(AnalysisContext)
  if (!ctx) throw new Error('useAnalysis must be used inside <AnalysisProvider>')
  return ctx
}
