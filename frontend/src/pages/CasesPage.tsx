import React, { useEffect, useState } from 'react'
import { casesApi } from '../services/api'
import { Case } from '../types'
import { Card, Button, Badge, Spinner, Modal, Input, EmptyState } from '../components/common'
import { formatDate, clsx, canManageCases, canDeleteCases } from '../utils'
import { authStore } from '../store/auth'

function priorityColor(p: string) {
  const map: Record<string, string> = {
    critical: 'text-red-400 bg-red-500/10 border-red-500/30',
    high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
    low: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
  }
  return map[p] || map['low']
}

function statusColor(s: string) {
  const map: Record<string, string> = {
    open: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
    in_progress: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
    resolved: 'text-green-400 bg-green-500/10 border-green-500/30',
    closed: 'text-slate-400 bg-slate-500/10 border-slate-500/30',
  }
  return map[s] || map['open']
}

function CreateCaseModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({ title: '', description: '', priority: 'medium' })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      await casesApi.create(form)
      onCreated()
      onClose()
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to create case')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Modal open onClose={onClose} title="Create New Case">
      <form onSubmit={submit} className="flex flex-col gap-4">
        <Input label="Title" value={form.title} onChange={e => setForm(p => ({ ...p, title: e.target.value }))} required placeholder="e.g. Phishing campaign targeting finance" />
        <div className="flex flex-col gap-1">
          <label className="text-sm text-slate-400">Description</label>
          <textarea value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))}
            className="px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-slate-100 text-sm focus:outline-none focus:border-blue-500 min-h-[80px] resize-none placeholder-slate-500"
            placeholder="Optional: describe the case" />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-sm text-slate-400">Priority</label>
          <select value={form.priority} onChange={e => setForm(p => ({ ...p, priority: e.target.value }))}
            className="px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-slate-100 text-sm focus:outline-none focus:border-blue-500">
            {['low', 'medium', 'high', 'critical'].map(p => (
              <option key={p} value={p} className="capitalize">{p}</option>
            ))}
          </select>
        </div>
        {error && <p className="text-red-400 text-sm">{error}</p>}
        <div className="flex gap-2 justify-end pt-2">
          <Button variant="secondary" type="button" onClick={onClose}>Cancel</Button>
          <Button type="submit" loading={loading}>Create Case</Button>
        </div>
      </form>
    </Modal>
  )
}

function CaseDetailModal({ caseItem, onClose, onRefresh }: { caseItem: Case; onClose: () => void; onRefresh: () => void }) {
  const [note, setNote] = useState('')
  const [addingNote, setAddingNote] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const notes = caseItem.notes ? JSON.parse(caseItem.notes) : []
  const role = authStore.getUser()?.role
  const canManage = canManageCases(role)
  const canDelete = canDeleteCases(role)

  const addNote = async () => {
    if (!note.trim()) return
    setAddingNote(true)
    try {
      await casesApi.addNote(caseItem.id, note)
      setNote('')
      onRefresh()
      onClose()
    } catch { /* ignore */ } finally {
      setAddingNote(false)
    }
  }

  const updateStatus = async (status: string) => {
    try {
      await casesApi.updateStatus(caseItem.id, status)
      onRefresh()
      onClose()
    } catch { /* ignore */ }
  }

  const deleteCase = async () => {
    if (!window.confirm('Permanently delete this case? This cannot be undone.')) return
    setDeleting(true)
    try {
      await casesApi.delete(caseItem.id)
      onRefresh()
      onClose()
    } catch (e: any) {
      alert(e.response?.data?.detail || 'Failed to delete case')
      setDeleting(false)
    }
  }

  return (
    <Modal open onClose={onClose} title={`${caseItem.case_number} — ${caseItem.title}`}>
      <div className="flex flex-col gap-4">
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div><span className="text-slate-500">Status:</span>
            <span className={clsx('ml-2 px-2 py-0.5 rounded border text-xs', statusColor(caseItem.status))}>{caseItem.status}</span>
          </div>
          <div><span className="text-slate-500">Priority:</span>
            <span className={clsx('ml-2 px-2 py-0.5 rounded border text-xs', priorityColor(caseItem.priority))}>{caseItem.priority}</span>
          </div>
          <div><span className="text-slate-500">Created:</span> <span className="text-slate-300">{formatDate(caseItem.created_at)}</span></div>
          {caseItem.description && <div className="col-span-2 text-slate-300">{caseItem.description}</div>}
        </div>

        {/* Status actions */}
        {canManage ? (
          <div>
            <p className="text-xs text-slate-500 mb-2">Update Status</p>
            <div className="flex gap-2 flex-wrap">
              {['open', 'in_progress', 'resolved', 'closed'].map(s => (
                <button key={s} onClick={() => updateStatus(s)}
                  disabled={caseItem.status === s}
                  className={clsx('px-3 py-1 rounded text-xs border transition-all capitalize disabled:opacity-40', statusColor(s))}>
                  {s.replace('_', ' ')}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <p className="text-xs text-slate-500">🔒 Read-only — ask an admin or analyst to change case status.</p>
        )}

        {/* Notes */}
        <div>
          <p className="text-xs text-slate-500 mb-2">Case Notes</p>
          {notes.length === 0 ? (
            <p className="text-slate-600 text-xs">No notes yet</p>
          ) : (
            <div className="flex flex-col gap-2 max-h-40 overflow-y-auto mb-2">
              {notes.map((n: any, i: number) => (
                <div key={i} className="bg-slate-800/50 rounded-lg p-3 text-xs">
                  <p className="text-slate-300">{n.text}</p>
                  <p className="text-slate-600 mt-1">{n.by} · {new Date(n.at).toLocaleString()}</p>
                </div>
              ))}
            </div>
          )}
          <div className="flex gap-2 mt-2">
            <input value={note} onChange={e => setNote(e.target.value)}
              className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-blue-500 placeholder-slate-500"
              placeholder="Add a note..." onKeyDown={e => e.key === 'Enter' && addNote()} />
            <Button size="sm" loading={addingNote} onClick={addNote}>Add</Button>
          </div>
        </div>

        {canDelete && (
          <div className="pt-2 border-t border-slate-800 flex justify-end">
            <Button variant="danger" size="sm" loading={deleting} onClick={deleteCase}>
              🗑️ Delete Case
            </Button>
          </div>
        )}
      </div>
    </Modal>
  )
}

export default function CasesPage() {
  const [cases, setCases] = useState<Case[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [selected, setSelected] = useState<Case | null>(null)
  const [statusFilter, setStatusFilter] = useState('')
  const canManage = canManageCases(authStore.getUser()?.role)

  const load = () => {
    setLoading(true)
    casesApi.list({ status: statusFilter || undefined, per_page: 50 })
      .then(r => setCases(r.data.cases || []))
      .catch(console.error)
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [statusFilter])

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Cases</h1>
          <p className="text-slate-400 text-sm mt-1">Investigation case management</p>
        </div>
        {canManage && <Button onClick={() => setShowCreate(true)}>+ New Case</Button>}
      </div>

      <Card>
        {/* Status filter */}
        <div className="flex gap-2 mb-5 flex-wrap">
          {['', 'open', 'in_progress', 'resolved', 'closed'].map(s => (
            <button key={s} onClick={() => setStatusFilter(s)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all capitalize ${statusFilter === s ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200 bg-slate-800'}`}>
              {s || 'All'}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="flex justify-center py-8"><Spinner /></div>
        ) : cases.length === 0 ? (
          <EmptyState icon="📁" title="No cases found" message="Create a case to start an investigation" />
        ) : (
          <div className="flex flex-col gap-3">
            {cases.map(c => (
              <div key={c.id}
                className="flex items-center gap-4 p-4 rounded-xl border border-slate-700/50 hover:bg-slate-800/30 cursor-pointer transition-all"
                onClick={() => setSelected(c)}>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs text-slate-500 font-mono">{c.case_number}</span>
                    <span className={clsx('text-xs px-2 py-0.5 rounded border', statusColor(c.status))}>{c.status.replace('_', ' ')}</span>
                    <span className={clsx('text-xs px-2 py-0.5 rounded border', priorityColor(c.priority))}>{c.priority}</span>
                  </div>
                  <p className="text-sm font-medium text-slate-200">{c.title}</p>
                  {c.description && <p className="text-xs text-slate-500 mt-0.5 truncate">{c.description}</p>}
                </div>
                <div className="text-right text-xs text-slate-600 flex-shrink-0">
                  <p>{formatDate(c.created_at)}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {showCreate && <CreateCaseModal onClose={() => setShowCreate(false)} onCreated={load} />}
      {selected && <CaseDetailModal caseItem={selected} onClose={() => setSelected(null)} onRefresh={load} />}
    </div>
  )
}
