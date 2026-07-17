import React, { useEffect, useState } from 'react'
import { alertsApi } from '../services/api'
import { Alert } from '../types'
import { Card, Button, Badge, Spinner, EmptyState, Table } from '../components/common'
import { timeAgo, canManageAlerts } from '../utils'
import { authStore } from '../store/auth'
import { ExportButton } from '../components/ExportButton'

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<'all' | 'unacknowledged'>('all')
  const [acking, setAcking] = useState<Set<number>>(new Set())
  const canAck = canManageAlerts(authStore.getUser()?.role)

  const load = () => {
    setLoading(true)
    alertsApi.list({ acknowledged: filter === 'unacknowledged' ? false : undefined, per_page: 50 })
      .then(r => setAlerts(r.data.alerts))
      .catch(console.error)
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [filter])

  const acknowledge = async (id: number) => {
    setAcking(s => new Set(s).add(id))
    try {
      await alertsApi.acknowledge(id)
      setAlerts(prev => prev.map(a => a.id === id ? { ...a, is_acknowledged: true } : a))
    } catch { /* ignore */ } finally {
      setAcking(s => { const n = new Set(s); n.delete(id); return n })
    }
  }

  const unackCount = alerts.filter(a => !a.is_acknowledged).length

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Alerts</h1>
          <p className="text-slate-400 text-sm mt-1">Security alerts requiring attention</p>
        </div>
        <div className="flex items-center gap-3">
          {unackCount > 0 && (
            <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg px-4 py-2">
              <span className="text-orange-400 font-semibold">{unackCount} unacknowledged</span>
            </div>
          )}
          <ExportButton entity="alerts" />
        </div>
      </div>

      <Card>
        {/* Filters */}
        <div className="flex gap-2 mb-5">
          {(['all', 'unacknowledged'] as const).map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-all capitalize ${filter === f ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200 bg-slate-800'}`}>
              {f}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="flex justify-center py-8"><Spinner /></div>
        ) : alerts.length === 0 ? (
          <EmptyState icon="🔔" title="No alerts" message={filter === 'unacknowledged' ? 'All alerts acknowledged!' : 'No alerts yet'} />
        ) : (
          <div className="flex flex-col gap-2">
            {alerts.map(alert => (
              <div key={alert.id}
                className={`flex items-start gap-4 p-4 rounded-xl border transition-all ${alert.is_acknowledged ? 'border-slate-700/30 bg-slate-800/20 opacity-60' : 'border-slate-700/50 bg-slate-800/40'}`}>
                <Badge label={alert.severity} severity={alert.severity} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-slate-200">{alert.title}</p>
                  <p className="text-xs text-slate-400 mt-0.5">{alert.message}</p>
                  <p className="text-xs text-slate-600 mt-1">{timeAgo(alert.created_at)}</p>
                </div>
                {!alert.is_acknowledged && canAck && (
                  <Button variant="ghost" size="sm" loading={acking.has(alert.id)} onClick={() => acknowledge(alert.id)}>
                    ✓ Ack
                  </Button>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}