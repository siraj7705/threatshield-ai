import React, { useEffect, useState } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  PieChart, Pie, Cell, ResponsiveContainer,
  LineChart, Line, CartesianGrid, Legend,
} from 'recharts'
import { dashboardApi } from '../services/api'
import { DashboardData } from '../types'
import { Card, Spinner, Badge, EmptyState } from '../components/common'
import { timeAgo, severityColor } from '../utils'

// ── Types ─────────────────────────────────────────────────────────────────────
interface TopDomain {
  domain: string
  threat_count: number
  avg_threat_score: number
  is_known_malicious: boolean
  is_repeat_offender: boolean
}

interface TimelineEntry {
  date: string
  total: number
  critical: number
  high: number
  warning: number
}

interface LocationEntry {
  country: string
  city?: string
  threat_count: number
  lat?: number
  lng?: number
}

// ── StatCard ──────────────────────────────────────────────────────────────────
interface StatCardProps {
  icon: string
  label: string
  value: number
  color?: string
}
function StatCard({ icon, label, value, color = '#3b82f6' }: StatCardProps) {
  return (
    <Card className="flex items-center gap-4">
      <div className="w-12 h-12 rounded-xl flex items-center justify-center text-xl flex-shrink-0"
        style={{ backgroundColor: `${color}15`, border: `1px solid ${color}30` }}>
        {icon}
      </div>
      <div>
        <p className="text-2xl font-bold text-white">{value.toLocaleString()}</p>
        <p className="text-sm text-slate-400">{label}</p>
      </div>
    </Card>
  )
}

// ── Main Component ────────────────────────────────────────────────────────────
export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null)
  const [domains, setDomains] = useState<TopDomain[]>([])
  const [timeline, setTimeline] = useState<TimelineEntry[]>([])
  const [locations, setLocations] = useState<LocationEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [days, setDays] = useState(30)

  useEffect(() => {
    setLoading(true)
    Promise.all([
      dashboardApi.stats(days),
      dashboardApi.topThreatDomains(10, days),
      dashboardApi.timeline(days),
      dashboardApi.locationMap(days),
    ])
      .then(([statsRes, domainsRes, timelineRes, locRes]) => {
        setData(statsRes.data)
        setDomains(domainsRes.data || [])
        setTimeline(timelineRes.data || [])
        setLocations(locRes.data || [])
      })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [days])

  if (loading) return (
    <div className="flex items-center justify-center h-full">
      <Spinner size="lg" />
    </div>
  )

  const stats = data?.stats
  const pieData = Object.entries(data?.severity_distribution || {}).map(([name, value]) => ({ name, value: value as number }))
  const typeData = Object.entries(data?.top_threat_types || {}).slice(0, 6).map(([name, count]) => ({ name, count }))

  // Format timeline dates to short labels
  const timelineFormatted = timeline.map(t => ({
    ...t,
    label: new Date(t.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
  }))

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-slate-400 text-sm mt-1">Email threat intelligence overview</p>
        </div>
        {/* Days selector */}
        <div className="flex gap-2">
          {[7, 30, 90].map(d => (
            <button
              key={d}
              onClick={() => setDays(d)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${days === d
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-800 text-slate-400 hover:text-white'
                }`}
            >
              {d}d
            </button>
          ))}
        </div>
      </div>

      {/* Stat grid row 1 */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon="📧" label="Total Emails" value={stats?.total_emails || 0} />
        <StatCard icon="🚨" label="Threats Detected" value={stats?.threat_emails || 0} color="#ef4444" />
        <StatCard icon="✅" label="Safe Emails" value={stats?.safe_emails || 0} color="#22c55e" />
        <StatCard icon="🔔" label="Unacknowledged Alerts" value={stats?.unacknowledged_alerts || 0} color="#f97316" />
      </div>

      {/* Stat grid row 2 */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon="🚫" label="Blocked" value={stats?.blocked_emails || 0} color="#ef4444" />
        <StatCard icon="📦" label="Quarantined" value={stats?.quarantined_emails || 0} color="#eab308" />
        <StatCard icon="⏳" label="Pending Review" value={stats?.pending_emails || 0} color="#6366f1" />
        <StatCard icon="📁" label="Active Cases" value={stats?.active_cases || 0} color="#06b6d4" />
      </div>

      {/* Charts row 1 — existing */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <h2 className="text-sm font-semibold text-slate-300 mb-4">Top Threat Types</h2>
          {typeData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={typeData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, color: '#f1f5f9' }} />
                <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState icon="📊" title="No threat data yet" message="Upload emails to see analysis" />
          )}
        </Card>

        <Card>
          <h2 className="text-sm font-semibold text-slate-300 mb-4">Severity Distribution</h2>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                  {pieData.map((entry) => (
                    <Cell key={entry.name} fill={severityColor(entry.name)} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState icon="🥧" title="No distribution data" />
          )}
        </Card>
      </div>

      {/* NEW: Threat Timeline */}
      <Card>
        <h2 className="text-sm font-semibold text-slate-300 mb-4">📈 Threat Timeline — last {days} days</h2>
        {timelineFormatted.length > 0 ? (
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={timelineFormatted} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="label" tick={{ fill: '#94a3b8', fontSize: 10 }} interval="preserveStartEnd" />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, color: '#f1f5f9' }} />
              <Legend wrapperStyle={{ fontSize: 12, color: '#94a3b8' }} />
              <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} dot={false} name="Critical" />
              <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={2} dot={false} name="High" />
              <Line type="monotone" dataKey="warning" stroke="#eab308" strokeWidth={2} dot={false} name="Warning" />
              <Line type="monotone" dataKey="total" stroke="#3b82f6" strokeWidth={2} dot={false} name="Total" strokeDasharray="4 2" />
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <EmptyState icon="📈" title="No timeline data" message="No threats detected in this period" />
        )}
      </Card>

      {/* NEW: Top Threat Domains */}
      <Card>
        <h2 className="text-sm font-semibold text-slate-300 mb-4">🌐 Top Threat Domains</h2>
        {domains.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 border-b border-slate-700">
                  <th className="pb-2 font-medium">Domain</th>
                  <th className="pb-2 font-medium text-center">Threats</th>
                  <th className="pb-2 font-medium text-center">Avg Score</th>
                  <th className="pb-2 font-medium text-center">Flags</th>
                </tr>
              </thead>
              <tbody>
                {domains.map((d, i) => (
                  <tr key={d.domain} className="border-b border-slate-700/30 last:border-0 hover:bg-slate-800/30">
                    <td className="py-2.5 pr-4">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500 text-xs w-4">{i + 1}</span>
                        <span className="text-slate-200 font-mono text-xs">{d.domain}</span>
                      </div>
                    </td>
                    <td className="py-2.5 text-center">
                      <span className="text-red-400 font-semibold">{d.threat_count}</span>
                    </td>
                    <td className="py-2.5 text-center">
                      <span className={`font-semibold ${d.avg_threat_score >= 80 ? 'text-red-400' :
                          d.avg_threat_score >= 60 ? 'text-orange-400' : 'text-yellow-400'
                        }`}>
                        {d.avg_threat_score.toFixed(1)}
                      </span>
                    </td>
                    <td className="py-2.5 text-center">
                      <div className="flex gap-1 justify-center flex-wrap">
                        {d.is_known_malicious && <span className="px-1.5 py-0.5 bg-red-900/40 text-red-400 rounded text-xs">malicious</span>}
                        {d.is_repeat_offender && <span className="px-1.5 py-0.5 bg-orange-900/40 text-orange-400 rounded text-xs">repeat</span>}
                        {!d.is_known_malicious && !d.is_repeat_offender && <span className="text-slate-600 text-xs">—</span>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState icon="🌐" title="No domain data yet" message="Upload threat emails to see sender domains" />
        )}
      </Card>

      {/* NEW: Location Map (text-based — top countries) */}
      <Card>
        <h2 className="text-sm font-semibold text-slate-300 mb-4">📍 Threat Origins by Country</h2>
        {locations.length > 0 ? (
          <div className="space-y-2">
            {locations.slice(0, 10).map((loc, i) => {
              const maxCount = locations[0]?.threat_count || 1
              const pct = Math.round((loc.threat_count / maxCount) * 100)
              return (
                <div key={`${loc.country}-${loc.city}-${i}`} className="flex items-center gap-3">
                  <span className="text-slate-500 text-xs w-4 flex-shrink-0">{i + 1}</span>
                  <span className="text-slate-300 text-sm w-36 flex-shrink-0 truncate">
                    {loc.country}{loc.city ? ` · ${loc.city}` : ''}
                  </span>
                  <div className="flex-1 bg-slate-800 rounded-full h-2 overflow-hidden">
                    <div
                      className="h-2 rounded-full bg-gradient-to-r from-red-600 to-orange-500 transition-all duration-500"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-red-400 font-semibold text-sm w-8 text-right flex-shrink-0">
                    {loc.threat_count}
                  </span>
                </div>
              )
            })}
          </div>
        ) : (
          <EmptyState icon="📍" title="No location data" message="Location data comes from email headers and IP analysis" />
        )}
      </Card>

      {/* Recent alerts */}
      <Card>
        <h2 className="text-sm font-semibold text-slate-300 mb-4">Recent Alerts</h2>
        {data?.recent_alerts?.length ? (
          <div className="flex flex-col gap-2">
            {data.recent_alerts.map(alert => (
              <div key={alert.id} className="flex items-start gap-3 py-3 border-b border-slate-700/30 last:border-0">
                <Badge label={alert.severity} severity={alert.severity} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-slate-200">{alert.title}</p>
                  <p className="text-xs text-slate-500 truncate">{alert.message}</p>
                </div>
                <span className="text-xs text-slate-600 flex-shrink-0">{timeAgo(alert.created_at)}</span>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState icon="🔔" title="No alerts" message="All quiet — no recent alerts" />
        )}
      </Card>
    </div>
  )
}