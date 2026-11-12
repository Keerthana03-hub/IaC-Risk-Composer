/**
 * Projects.jsx
 * ------------
 * Projects / Workspace Manager.
 * Replaces and upgrades the legacy "Project History" page.
 * Developers can create, rename, manage, and open their infrastructure workspaces.
 */

import React, { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  FolderGit2,
  Plus,
  Search,
  Clock,
  MoreVertical,
  Trash2,
  Edit2,
  ExternalLink,
  ShieldAlert,
  Upload,
  Calendar,
  Layers,
} from 'lucide-react'

import { createProject, deleteProject, updateProject } from '../api'
import { useAnalysis } from '../context/AnalysisContext'
import { isRealSeverity } from '../utils/risk'
import { formatDateTime, timeAgo } from '../utils/format'
import { friendlyError } from '../utils/errors'

import PageHeader from '../components/common/PageHeader'
import ErrorBanner from '../components/common/ErrorBanner'
import EmptyState from '../components/common/EmptyState'
import SeverityBadge from '../components/common/SeverityBadge'
import Modal from '../components/common/Modal'
import ConfirmDialog from '../components/common/ConfirmDialog'
import { CardSkeleton } from '../components/common/Skeleton'

export default function Projects() {
  const navigate = useNavigate()
  const { projects, refreshProjects, selectProject } = useAnalysis()

  const [search, setSearch] = useState('')
  const [filterRisk, setFilterRisk] = useState('all')
  const [sortBy, setSortBy] = useState('updated') // 'updated' | 'name' | 'findings'
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // Create Project Modal state
  const [createModalOpen, setCreateModalOpen] = useState(false)
  const [newProjectName, setNewProjectName] = useState('')
  const [newProjectDesc, setNewProjectDesc] = useState('')
  const [createBusy, setCreateBusy] = useState(false)

  // Edit Project Modal state
  const [editProject, setEditProject] = useState(null)
  const [editName, setEditName] = useState('')
  const [editDesc, setEditDesc] = useState('')
  const [editBusy, setEditBusy] = useState(false)

  // Delete Project Confirm state
  const [pendingDelete, setPendingDelete] = useState(null)
  const [deleteBusy, setDeleteBusy] = useState(false)

  // Filter & sort projects
  const filteredProjects = useMemo(() => {
    return projects
      .filter((p) => {
        if (filterRisk !== 'all' && p.overall_risk_level?.toLowerCase() !== filterRisk) {
          return false
        }
        if (!search.trim()) return true
        const q = search.toLowerCase()
        return (
          p.name.toLowerCase().includes(q) ||
          (p.description || '').toLowerCase().includes(q)
        )
      })
      .sort((a, b) => {
        if (sortBy === 'name') return a.name.localeCompare(b.name)
        if (sortBy === 'findings') return (b.findings_count || 0) - (a.findings_count || 0)
        return new Date(b.updated_at || b.created_at) - new Date(a.updated_at || a.created_at)
      })
  }, [projects, search, filterRisk, sortBy])

  async function handleCreateProject(e) {
    e.preventDefault()
    if (!newProjectName.trim()) return
    setCreateBusy(true)
    setError('')
    try {
      const created = await createProject({
        name: newProjectName.trim(),
        description: newProjectProjectDesc.trim(),
      })
      await refreshProjects()
      setCreateModalOpen(false)
      setNewProjectName('')
      setNewProjectDesc('')
      selectProject(created.id)
    } catch (err) {
      setError(friendlyError(err, 'Failed to create workspace project.'))
    } finally {
      setCreateBusy(false)
    }
  }

  function openEditModal(proj, e) {
    e.stopPropagation()
    setEditProject(proj)
    setEditName(proj.name)
    setEditDesc(proj.description || '')
  }

  async function handleUpdateProject(e) {
    e.preventDefault()
    if (!editProject || !editName.trim()) return
    setEditBusy(true)
    setError('')
    try {
      await updateProject(editProject.id, {
        name: editName.trim(),
        description: editDesc.trim(),
      })
      await refreshProjects()
      setEditProject(null)
    } catch (err) {
      setError(friendlyError(err, 'Failed to update project.'))
    } finally {
      setEditBusy(false)
    }
  }

  async function handleDeleteConfirm() {
    if (!pendingDelete) return
    setDeleteBusy(true)
    setError('')
    try {
      await deleteProject(pendingDelete.id)
      await refreshProjects()
      setPendingDelete(null)
    } catch (err) {
      setError(friendlyError(err, 'Failed to delete project.'))
    } finally {
      setDeleteBusy(false)
    }
  }

  function handleOpenProject(proj) {
    selectProject(proj.id)
    if (proj.latest_analysis_id) {
      navigate(`/analyze?id=${proj.latest_analysis_id}`)
    } else {
      navigate(`/analyze?new=1&project_id=${proj.id}`)
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Projects"
        description="Organize your infrastructure configurations into isolated workspaces, track scan history, and remediate risks."
        actions={
          <button
            onClick={() => setCreateModalOpen(true)}
            className="btn-primary text-xs font-semibold py-2 px-3.5 shadow-sm"
          >
            <Plus className="h-4 w-4" /> Create Project
          </button>
        }
      />

      {error && <ErrorBanner message={error} />}

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search projects by name or description…"
            className="input pl-9 text-xs"
          />
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <select
            value={filterRisk}
            onChange={(e) => setFilterRisk(e.target.value)}
            className="input w-auto text-xs py-2"
          >
            <option value="all">All Risk Levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="input w-auto text-xs py-2"
          >
            <option value="updated">Recently Modified</option>
            <option value="name">Project Name (A-Z)</option>
            <option value="findings">Most Findings</option>
          </select>
        </div>
      </div>

      {/* Projects Grid */}
      {projects.length === 0 ? (
        <div className="card">
          <EmptyState
            icon={FolderGit2}
            title="No projects created yet"
            description="Create your first infrastructure project to organize Terraform files and threat reports."
            actionLabel="Create Project"
            onAction={() => setCreateModalOpen(true)}
          />
        </div>
      ) : filteredProjects.length === 0 ? (
        <div className="card text-center py-12 text-xs text-slate-500">
          No projects match your filter criteria.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {filteredProjects.map((proj) => {
            const hasAnalyses = proj.analyses_count > 0
            return (
              <div
                key={proj.id}
                className="card card-hover flex flex-col justify-between p-5 border border-slate-200/90 dark:border-slate-800 relative group"
              >
                <div>
                  {/* Top: Icon + Name + Actions */}
                  <div className="flex items-start justify-between gap-3 mb-3">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="h-10 w-10 rounded-xl bg-blue-50 dark:bg-blue-950/60 border border-blue-100 dark:border-blue-900/60 flex items-center justify-center text-blue-600 dark:text-blue-400 flex-shrink-0 shadow-2xs">
                        <FolderGit2 className="h-5 w-5" />
                      </div>
                      <div className="min-w-0">
                        <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 truncate leading-snug group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                          {proj.name}
                        </h3>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono mt-0.5 truncate">
                          {proj.id}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-1">
                      <button
                        onClick={(e) => openEditModal(proj, e)}
                        className="icon-btn hover:text-slate-900 dark:hover:text-slate-100"
                        title="Edit Project"
                      >
                        <Edit2 className="h-3.5 w-3.5" />
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          setPendingDelete(proj)
                        }}
                        className="icon-btn hover:text-rose-600 dark:hover:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/40"
                        title="Delete Project"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* Description */}
                  <p className="text-xs text-slate-600 dark:text-slate-400 line-clamp-2 leading-relaxed mb-4 min-h-[32px]">
                    {proj.description || 'No description provided.'}
                  </p>

                  {/* Status Banner */}
                  <div className="inset-box p-3 space-y-2 mb-4 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500 dark:text-slate-400 text-[11px]">Posture Status</span>
                      {isRealSeverity(proj.overall_risk_level) ? (
                        <SeverityBadge severity={proj.overall_risk_level} />
                      ) : (
                        <span className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">
                          Not Assessed
                        </span>
                      )}
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500 dark:text-slate-400 text-[11px]">Findings</span>
                      <span className="font-bold text-slate-800 dark:text-slate-200">
                        {proj.findings_count} total
                        {proj.critical_count > 0 && (
                          <span className="text-rose-600 dark:text-rose-400 font-bold ml-1">
                            ({proj.critical_count} critical)
                          </span>
                        )}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500 dark:text-slate-400 text-[11px]">Total Analyses</span>
                      <span className="font-mono text-slate-700 dark:text-slate-300 font-semibold">
                        {proj.analyses_count}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Footer Actions */}
                <div className="pt-3 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-xs">
                  <span className="text-[11px] text-slate-400 dark:text-slate-500 flex items-center gap-1 truncate max-w-[130px]">
                    <Clock className="h-3 w-3 flex-shrink-0" />
                    {proj.last_analyzed ? timeAgo(proj.last_analyzed) : 'No scans yet'}
                  </span>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => navigate(`/analyze?new=1&project_id=${proj.id}`)}
                      className="btn-ghost text-xs py-1 px-2.5 font-medium"
                      title="Run new scan for this project"
                    >
                      <Upload className="h-3.5 w-3.5" />
                    </button>
                    <button
                      onClick={() => handleOpenProject(proj)}
                      className="btn-primary text-xs py-1.5 px-3 font-semibold shadow-xs"
                    >
                      {hasAnalyses ? 'Open Project' : 'Start Scan'}
                    </button>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Create Project Modal */}
      <Modal
        open={createModalOpen}
        onClose={() => setCreateModalOpen(false)}
        title="Create New Project"
        subtitle="Set up an isolated workspace for your infrastructure architecture."
      >
        <form onSubmit={handleCreateProject} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1.5">
              Project Name <span className="text-rose-500">*</span>
            </label>
            <input
              type="text"
              value={newProjectName}
              onChange={(e) => setNewProjectName(e.target.value)}
              className="input text-xs"
              placeholder="e.g. Payment Gateway Infrastructure"
              required
              autoFocus
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1.5">
              Description (Optional)
            </label>
            <textarea
              value={newProjectDesc}
              onChange={(e) => setNewProjectDesc(e.target.value)}
              className="input text-xs h-24 resize-none"
              placeholder="Primary PCI-DSS payment processing tier, RDS databases, and VPC networking."
            />
          </div>

          <div className="flex justify-end gap-2.5 pt-3 border-t border-slate-100">
            <button
              type="button"
              onClick={() => setCreateModalOpen(false)}
              className="btn-ghost text-xs py-2 px-3.5 font-semibold"
              disabled={createBusy}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn-primary text-xs py-2 px-4 font-semibold"
              disabled={createBusy || !newProjectName.trim()}
            >
              {createBusy ? 'Creating...' : 'Create Project'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Edit Project Modal */}
      <Modal
        open={!!editProject}
        onClose={() => setEditProject(null)}
        title="Edit Project"
        subtitle={`Update details for ${editProject?.name}`}
      >
        <form onSubmit={handleUpdateProject} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1.5">
              Project Name <span className="text-rose-500">*</span>
            </label>
            <input
              type="text"
              value={editName}
              onChange={(e) => setEditName(e.target.value)}
              className="input text-xs"
              required
              autoFocus
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1.5">
              Description
            </label>
            <textarea
              value={editDesc}
              onChange={(e) => setEditDesc(e.target.value)}
              className="input text-xs h-24 resize-none"
            />
          </div>

          <div className="flex justify-end gap-2.5 pt-3 border-t border-slate-100">
            <button
              type="button"
              onClick={() => setEditProject(null)}
              className="btn-ghost text-xs py-2 px-3.5 font-semibold"
              disabled={editBusy}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn-primary text-xs py-2 px-4 font-semibold"
              disabled={editBusy || !editName.trim()}
            >
              {editBusy ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={!!pendingDelete}
        title="Delete Project Workspace?"
        message={
          pendingDelete &&
          `Are you sure you want to delete "${pendingDelete.name}"? All associated analyses and reports will also be removed permanently. This action cannot be undone.`
        }
        confirmLabel="Delete Project"
        busy={deleteBusy}
        onConfirm={handleDeleteConfirm}
        onCancel={() => setPendingDelete(null)}
      />
    </div>
  )
}
