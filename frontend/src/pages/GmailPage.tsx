import React, { useEffect, useState } from 'react'
import { api } from '../services/api'
import { Card, Button, Spinner, EmptyState } from '../components/common'
import { clsx } from '../utils'

interface GmailStatus {
  credentials_file: boolean
  token_file: boolean
  authenticated: boolean
  watching: boolean
  last_history_id: string | null
  pubsub_topic: string
  admin_email: string
  webhook_url: string
}

function StatusRow({ label, ok, value }: { label: string; ok: boolean; value?: string }) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-slate-700/30 last:border-0">
      <div className="flex items-center gap-3">
        <span className={clsx('w-2 h-2 rounded-full flex-shrink-0', ok ? 'bg-green-400' : 'bg-red-400')} />
        <span className="text-sm text-slate-300">{label}</span>
      </div>
      {value && <span className="text-xs text-slate-500 font-mono truncate max-w-xs">{value}</span>}
    </div>
  )
}

export default function GmailPage() {
  const [status, setStatus] = useState<GmailStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState('')
  const [message, setMessage] = useState<{ text: string; ok: boolean } | null>(null)
  const [batchCount, setBatchCount] = useState(10)

  const loadStatus = () => {
    setLoading(true)
    api.get('/api/gmail/status')
      .then(r => setStatus(r.data))
      .catch(console.error)
      .finally(() => setLoading(false))
  }

  useEffect(() => { loadStatus() }, [])

  const act = async (label: string, fn: () => Promise<any>) => {
    setActionLoading(label)
    setMessage(null)
    try {
      const res = await fn()
      setMessage({ text: res.data.message || 'Done!', ok: true })
      loadStatus()
    } catch (e: any) {
      setMessage({ text: e.response?.data?.detail || 'Action failed', ok: false })
    } finally {
      setActionLoading('')
    }
  }

  return (
    <div className="p-6 max-w-3xl">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Gmail Integration</h1>
        <p className="text-slate-400 text-sm mt-1">Auto-scan every incoming email via Gmail + Google Cloud Pub/Sub</p>
      </div>

      {/* How it works */}
      <Card className="mb-6">
        <h2 className="text-sm font-semibold text-slate-300 mb-4">How It Works</h2>
        <div className="flex flex-col gap-3">
          {[
            { step: '1', label: 'Email arrives in Gmail inbox' },
            { step: '2', label: 'Gmail notifies ThreatShield via Google Pub/Sub' },
            { step: '3', label: 'ThreatShield fetches & scans the email (NLP + Headers + Score)' },
            { step: '4', label: 'Threat detected → move to Quarantine label + notify admin' },
            { step: '5', label: 'Safe email → apply ThreatShield-Safe label' },
          ].map(({ step, label }) => (
            <div key={step} className="flex items-center gap-3">
              <div className="w-6 h-6 rounded-full bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-xs font-bold text-blue-400 flex-shrink-0">{step}</div>
              <span className="text-sm text-slate-300">{label}</span>
            </div>
          ))}
        </div>
      </Card>

      {/* Status */}
      <Card className="mb-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-slate-300">Integration Status</h2>
          <Button variant="ghost" size="sm" onClick={loadStatus}>↻ Refresh</Button>
        </div>

        {loading ? (
          <div className="flex justify-center py-6"><Spinner /></div>
        ) : status ? (
          <div>
            <StatusRow label="credentials.json present" ok={status.credentials_file} />
            <StatusRow label="Gmail token (authenticated)" ok={status.authenticated} />
            <StatusRow label="Pub/Sub topic configured" ok={status.pubsub_topic !== 'not configured'} value={status.pubsub_topic} />
            <StatusRow label="Admin email configured" ok={status.admin_email !== 'not configured'} value={status.admin_email} />
            <StatusRow label="Webhook URL" ok={true} value={status.webhook_url} />
            <StatusRow label="Currently watching inbox" ok={status.watching}
              value={status.watching ? `History ID: ${status.last_history_id}` : 'Not watching'} />
          </div>
        ) : (
          <EmptyState icon="❌" title="Could not load status" />
        )}
      </Card>

      {/* Actions */}
      <Card className="mb-6">
        <h2 className="text-sm font-semibold text-slate-300 mb-4">Controls</h2>

        {message && (
          <div className={clsx('mb-4 px-4 py-3 rounded-lg text-sm border', message.ok
            ? 'bg-green-500/10 border-green-500/30 text-green-400'
            : 'bg-red-500/10 border-red-500/30 text-red-400')}>
            {message.text}
          </div>
        )}

        <div className="flex flex-col gap-3">
          <div className="flex items-center justify-between p-4 bg-slate-800/40 rounded-xl">
            <div>
              <p className="text-sm font-medium text-slate-200">Start Gmail Watch</p>
              <p className="text-xs text-slate-500 mt-0.5">Begin monitoring inbox for new emails via Pub/Sub</p>
            </div>
            <Button
              loading={actionLoading === 'start'}
              onClick={() => act('start', () => api.post('/api/gmail/watch/start'))}>
              ▶ Start
            </Button>
          </div>

          <div className="flex items-center justify-between p-4 bg-slate-800/40 rounded-xl">
            <div>
              <p className="text-sm font-medium text-slate-200">Stop Gmail Watch</p>
              <p className="text-xs text-slate-500 mt-0.5">Pause inbox monitoring</p>
            </div>
            <Button variant="danger"
              loading={actionLoading === 'stop'}
              onClick={() => act('stop', () => api.post('/api/gmail/watch/stop'))}>
              ◼ Stop
            </Button>
          </div>

          <div className="flex items-center justify-between p-4 bg-slate-800/40 rounded-xl">
            <div>
              <p className="text-sm font-medium text-slate-200">Scan Recent Emails</p>
              <p className="text-xs text-slate-500 mt-0.5">Manually scan last N unscanned inbox emails</p>
            </div>
            <div className="flex items-center gap-2">
              <input type="number" min={1} max={50} value={batchCount}
                onChange={e => setBatchCount(Number(e.target.value))}
                className="w-16 px-2 py-1.5 bg-slate-800 border border-slate-600 rounded-lg text-sm text-slate-100 text-center focus:outline-none focus:border-blue-500" />
              <Button variant="secondary"
                loading={actionLoading === 'batch'}
                onClick={() => act('batch', () => api.post(`/api/gmail/scan/batch?max_emails=${batchCount}`))}>
                Scan
              </Button>
            </div>
          </div>
        </div>
      </Card>

      {/* Setup Guide */}
      <Card>
        <h2 className="text-sm font-semibold text-slate-300 mb-4">📋 Setup Guide</h2>
        <div className="flex flex-col gap-4 text-sm">
          {[
            {
              title: '1. Create Google Cloud Project',
              desc: 'Go to console.cloud.google.com → New Project → name it "ThreatShield"',
              link: 'https://console.cloud.google.com',
            },
            {
              title: '2. Enable APIs',
              desc: 'Enable Gmail API and Cloud Pub/Sub API in APIs & Services → Library',
              link: 'https://console.cloud.google.com/apis/library',
            },
            {
              title: '3. Create OAuth 2.0 Credentials',
              desc: 'APIs & Services → Credentials → Create Credentials → OAuth client ID → Desktop App → Download credentials.json → place in backend/',
              link: 'https://console.cloud.google.com/apis/credentials',
            },
            {
              title: '4. Create Pub/Sub Topic',
              desc: 'Pub/Sub → Topics → Create topic named "threatshield-gmail" → add gmail-api-push@system.gserviceaccount.com as Publisher',
              link: 'https://console.cloud.google.com/cloudpubsub/topic/list',
            },
            {
              title: '5. Create Pub/Sub Subscription',
              desc: 'Create Push subscription → set endpoint to your APP_BASE_URL/api/gmail/webhook (use ngrok for local dev)',
              link: 'https://console.cloud.google.com/cloudpubsub/subscription/list',
            },
            {
              title: '6. Update .env',
              desc: 'Set GMAIL_PUBSUB_TOPIC, GMAIL_ADMIN_EMAIL, GMAIL_WATCHER_EMAIL, APP_BASE_URL in your backend/.env',
            },
            {
              title: '7. Authenticate',
              desc: 'Run: python -c "from app.core.gmail_auth import get_credentials; get_credentials()" — browser will open for consent',
            },
            {
              title: '8. Start Watch',
              desc: 'Click "Start Gmail Watch" above — ThreatShield will now auto-scan every new inbox email 🚀',
            },
          ].map(({ title, desc, link }) => (
            <div key={title} className="flex gap-3">
              <div className="flex-1">
                <p className="font-medium text-slate-200">{title}</p>
                <p className="text-slate-500 text-xs mt-0.5">{desc}</p>
              </div>
              {link && (
                <a href={link} target="_blank" rel="noopener noreferrer"
                  className="text-blue-400 text-xs hover:underline flex-shrink-0 mt-0.5">Open →</a>
              )}
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}
