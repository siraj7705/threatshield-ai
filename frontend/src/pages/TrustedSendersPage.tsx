import React, { useEffect, useState } from 'react'
import { trustedSendersApi } from '../services/api'
import { TrustedSender } from '../types'
import { Card, Button, Spinner, EmptyState } from '../components/common'
import { formatDate, clsx } from '../utils'

export default function TrustedSendersPage() {
  const [senders, setSenders] = useState<TrustedSender[]>([])
  const [loading, setLoading] = useState(true)
  const [input, setInput] = useState('')
  const [nameInput, setNameInput] = useState('')
  const [adding, setAdding] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const load = () => {
    setLoading(true)
    trustedSendersApi.list()
      .then(r => setSenders(r.data))
      .catch(console.error)
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const add = async () => {
    const val = input.trim()
    if (!val) return
    setAdding(true)
    setError('')
    setSuccess('')
    try {
      await trustedSendersApi.add(val, nameInput.trim() || undefined)
      setInput('')
      setNameInput('')
      setSuccess(`"${val}" added to trusted list.`)
      load()
    } catch (e: any) {
      setError(e.response?.data?.detail || 'Failed to add')
    } finally {
      setAdding(false)
    }
  }

  const remove = async (id: number, email: string) => {
    try {
      await trustedSendersApi.remove(id)
      setSuccess(`"${email}" removed.`)
      setSenders(s => s.filter(x => x.id !== id))
    } catch {
      setError('Failed to remove')
    }
  }

  return (
    <div className="p-6 max-w-3xl">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">⭐ Trusted Senders</h1>
        <p className="text-slate-400 text-sm mt-1">
          Emails from trusted senders are never quarantined or blocked.
          Malicious URLs or very high-confidence threat phrases still generate a low-priority notice.
        </p>
      </div>

      {/* How it works */}
      <Card className="mb-6">
        <h2 className="text-sm font-semibold text-slate-300 mb-3">How It Works</h2>
        <div className="flex flex-col gap-2 text-sm text-slate-400">
          <div className="flex items-start gap-2">
            <span className="text-green-400 mt-0.5">✓</span>
            <span>Trusted sender email arrives → <span className="text-slate-200">scanned but never quarantined/blocked</span></span>
          </div>
          <div className="flex items-start gap-2">
            <span className="text-yellow-400 mt-0.5">⚠</span>
            <span>Trusted sender + phishing URL detected → <span className="text-slate-200">low-priority alert (possible compromised account)</span></span>
          </div>
          <div className="flex items-start gap-2">
            <span className="text-blue-400 mt-0.5">ℹ</span>
            <span>Trusted sender + strong threat phrase → <span className="text-slate-200">notice only, no action taken</span></span>
          </div>
          <div className="flex items-start gap-2">
            <span className="text-slate-500 mt-0.5">@</span>
            <span>Add a whole domain like <code className="text-blue-300 bg-slate-800 px-1 rounded">@company.com</code> to trust all emails from that domain</span>
          </div>
        </div>
      </Card>

      {/* Add form */}
      <Card className="mb-6">
        <h2 className="text-sm font-semibold text-slate-300 mb-4">Add Trusted Sender</h2>

        {error && (
          <div className="mb-3 px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">{error}</div>
        )}
        {success && (
          <div className="mb-3 px-3 py-2 rounded-lg bg-green-500/10 border border-green-500/20 text-green-400 text-sm">{success}</div>
        )}

        <div className="flex flex-col gap-3">
          <div className="flex gap-3">
            <div className="flex-1">
              <label className="text-xs text-slate-500 mb-1 block">Email or Domain *</label>
              <input
                type="text"
                value={input}
                onChange={e => { setInput(e.target.value); setError('') }}
                onKeyDown={e => e.key === 'Enter' && add()}
                placeholder="user@example.com  or  @company.com"
                className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
              />
            </div>
            <div className="flex-1">
              <label className="text-xs text-slate-500 mb-1 block">Label (optional)</label>
              <input
                type="text"
                value={nameInput}
                onChange={e => setNameInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && add()}
                placeholder="e.g. My Boss, Work Domain"
                className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
              />
            </div>
          </div>
          <div className="flex justify-end">
            <Button onClick={add} loading={adding} disabled={!input.trim()}>
              + Add to Trusted List
            </Button>
          </div>
        </div>

        {/* Quick add examples */}
        <div className="mt-4 pt-4 border-t border-slate-700/50">
          <p className="text-xs text-slate-500 mb-2">Quick examples:</p>
          <div className="flex flex-wrap gap-2">
            {['@gmail.com', '@company.com', 'boss@work.com', 'hr@myorg.com'].map(ex => (
              <button
                key={ex}
                onClick={() => setInput(ex)}
                className="text-xs px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 rounded border border-slate-700 transition-colors font-mono"
              >
                {ex}
              </button>
            ))}
          </div>
        </div>
      </Card>

      {/* List */}
      <Card>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-slate-300">
            Trusted List
            <span className="ml-2 text-slate-500 font-normal">({senders.length})</span>
          </h2>
          <Button variant="ghost" size="sm" onClick={load}>↻ Refresh</Button>
        </div>

        {loading ? (
          <div className="flex justify-center py-8"><Spinner /></div>
        ) : senders.length === 0 ? (
          <EmptyState
            icon="⭐"
            title="No trusted senders yet"
            message="Add email addresses or domains above to skip threat blocking for those senders."
          />
        ) : (
          <div className="flex flex-col gap-2">
            {senders.map(s => (
              <div key={s.id} className="flex items-center justify-between px-4 py-3 bg-slate-800/40 rounded-xl border border-slate-700/40 hover:border-slate-600/60 transition-colors group">
                <div className="flex items-center gap-3">
                  <div className={clsx(
                    'w-8 h-8 rounded-lg flex items-center justify-center text-sm flex-shrink-0',
                    s.email.startsWith('@')
                      ? 'bg-purple-500/20 border border-purple-500/30'
                      : 'bg-green-500/20 border border-green-500/30'
                  )}>
                    {s.email.startsWith('@') ? '🌐' : '👤'}
                  </div>
                  <div>
                    <p className="text-sm font-mono text-slate-200">{s.email}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      {s.name && <span className="text-xs text-slate-500">{s.name}</span>}
                      {s.email.startsWith('@') && (
                        <span className="text-xs text-purple-400 bg-purple-500/10 border border-purple-500/20 px-1.5 py-0.5 rounded">domain</span>
                      )}
                      {s.added_at && (
                        <span className="text-xs text-slate-600">Added {formatDate(s.added_at)}</span>
                      )}
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => remove(s.id, s.email)}
                  className="opacity-0 group-hover:opacity-100 text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10 px-2 py-1 rounded transition-all"
                >
                  Remove
                </button>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
