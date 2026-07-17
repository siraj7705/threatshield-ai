// ============================================================
// LOCATION: threatshield-ai/frontend/src/pages/SettingsPage.tsx
// ============================================================
import React, { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { gmailOAuthApi } from '../services/api'
import { Card, Button, Spinner, EmptyState } from '../components/common'
import { clsx, timeAgo } from '../utils'
import { GmailAccount } from '../types'
import { RetrainPanel } from '../components/RetrainPanel'

export default function SettingsPage() {
    const [account, setAccount] = useState<GmailAccount | null>(null)
    const [loading, setLoading] = useState(true)
    const [connecting, setConnecting] = useState(false)
    const [actionLoading, setActionLoading] = useState('')
    const [message, setMessage] = useState<{ text: string; ok: boolean } | null>(null)
    const [scanCount, setScanCount] = useState(10)
    const [searchParams, setSearchParams] = useSearchParams()

    const loadStatus = () => {
        setLoading(true)
        gmailOAuthApi.status()
            .then(r => setAccount(r.data))
            .catch(() => setAccount(null))
            .finally(() => setLoading(false))
    }

    useEffect(() => {
        loadStatus()
    }, [])

    useEffect(() => {
        const connected = searchParams.get('gmail_connected')
        if (connected === null) return

        if (connected === '1') {
            const address = searchParams.get('address')
            const watching = searchParams.get('watching')
            if (watching === '1') {
                setMessage({ text: `Gmail connected${address ? `: ${address}` : ''} — live monitoring is now on.`, ok: true })
            } else {
                setMessage({
                    text: `Gmail connected${address ? `: ${address}` : ''}, but live monitoring couldn't start automatically. You can try starting it below.`,
                    ok: true,
                })
            }
            loadStatus()
        } else {
            const reason = searchParams.get('reason') || 'unknown_error'
            const friendly: Record<string, string> = {
                access_denied: 'You declined the Google consent screen — Gmail was not connected.',
                token_exchange_failed: 'Google could not be reached to finish connecting. Please try again.',
                no_refresh_token: 'Google did not return the access needed for ongoing monitoring. Try disconnecting in your Google Account permissions, then reconnect.',
            }
            setMessage({ text: friendly[reason] || `Could not connect Gmail (${reason}).`, ok: false })
        }

        searchParams.delete('gmail_connected')
        searchParams.delete('address')
        searchParams.delete('reason')
        searchParams.delete('watching')
        setSearchParams(searchParams, { replace: true })
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [])

    const handleConnect = async () => {
        setConnecting(true)
        setMessage(null)
        try {
            const res = await gmailOAuthApi.connect()
            window.location.href = res.data.authorization_url
        } catch (e: any) {
            setMessage({ text: e.response?.data?.detail || 'Could not start Gmail connection.', ok: false })
            setConnecting(false)
        }
    }

    const act = async (label: string, fn: () => Promise<any>, successText?: string) => {
        setActionLoading(label)
        setMessage(null)
        try {
            const res = await fn()
            setMessage({ text: successText || res.data?.message || 'Done!', ok: true })
            loadStatus()
        } catch (e: any) {
            setMessage({ text: e.response?.data?.detail || 'Action failed', ok: false })
        } finally {
            setActionLoading('')
        }
    }

    const handleDisconnect = () => {
        if (!window.confirm('Disconnect your Gmail account? Live monitoring will stop. Past scanned emails are kept.')) return
        act('disconnect', () => gmailOAuthApi.disconnect(), 'Gmail account disconnected.')
    }

    return (
        <div className="p-6 max-w-3xl">
            <div className="mb-6">
                <h1 className="text-2xl font-bold text-white">Settings</h1>
                <p className="text-slate-400 text-sm mt-1">Manage your personal account preferences</p>
            </div>

            <Card className="mb-6">
                <div className="flex items-center justify-between mb-1">
                    <h2 className="text-sm font-semibold text-slate-300">My Gmail Connection</h2>
                    {!loading && (
                        <Button variant="ghost" size="sm" onClick={loadStatus}>↻ Refresh</Button>
                    )}
                </div>
                <p className="text-slate-500 text-xs mb-4">
                    Connect your own Gmail account so ThreatShield can scan your inbox and watch it for new threats in real time.
                </p>

                {message && (
                    <div className={clsx('mb-4 px-4 py-3 rounded-lg text-sm border', message.ok
                        ? 'bg-green-500/10 border-green-500/30 text-green-400'
                        : 'bg-red-500/10 border-red-500/30 text-red-400')}>
                        {message.text}
                    </div>
                )}

                {loading ? (
                    <div className="flex justify-center py-6"><Spinner /></div>
                ) : !account ? (
                    <div className="flex flex-col items-center justify-center py-10 text-center">
                        <div className="text-4xl mb-3">📭</div>
                        <h3 className="text-slate-300 font-semibold mb-1">No Gmail account connected</h3>
                        <p className="text-slate-500 text-sm mb-5 max-w-sm">
                            Connect your Gmail to scan emails and get live alerts for phishing, spam, and other threats — just for your inbox.
                        </p>
                        <Button loading={connecting} onClick={handleConnect}>
                            📬 Connect Gmail
                        </Button>
                    </div>
                ) : (
                    <div>
                        <div className="flex items-center justify-between p-4 bg-slate-800/40 rounded-xl mb-3">
                            <div className="flex items-center gap-3">
                                <span className={clsx('w-2.5 h-2.5 rounded-full flex-shrink-0', account.is_active ? 'bg-green-400' : 'bg-red-400')} />
                                <div>
                                    <p className="text-sm font-medium text-slate-200">{account.gmail_address}</p>
                                    <p className="text-xs text-slate-500 mt-0.5">
                                        {account.is_active ? 'Connected' : 'Disconnected'}
                                        {account.connected_at && ` · since ${timeAgo(account.connected_at)}`}
                                    </p>
                                </div>
                            </div>
                            <Button variant="danger" size="sm" loading={actionLoading === 'disconnect'} onClick={handleDisconnect}>
                                Disconnect
                            </Button>
                        </div>

                        {account.last_error && (
                            <div className="mb-3 px-4 py-2.5 rounded-lg text-xs border bg-orange-500/10 border-orange-500/30 text-orange-400">
                                ⚠ {account.last_error}
                            </div>
                        )}

                        <div className="flex items-center justify-between p-4 bg-slate-800/40 rounded-xl mb-3">
                            <div>
                                <p className="text-sm font-medium text-slate-200">Live Monitoring</p>
                                <p className="text-xs text-slate-500 mt-0.5">
                                    {account.is_watching
                                        ? 'New inbox emails are auto-scanned as they arrive.'
                                        : 'Turn on to auto-scan new inbox emails in near real-time.'}
                                </p>
                            </div>
                            {account.is_watching ? (
                                <Button variant="danger" size="sm" loading={actionLoading === 'watch_stop'}
                                    onClick={() => act('watch_stop', () => gmailOAuthApi.watchStop(), 'Live monitoring stopped.')}>
                                    ◼ Stop
                                </Button>
                            ) : (
                                <Button size="sm" loading={actionLoading === 'watch_start'}
                                    onClick={() => act('watch_start', () => gmailOAuthApi.watchStart(), 'Live monitoring started.')}>
                                    ▶ Start
                                </Button>
                            )}
                        </div>

                        <div className="flex items-center justify-between p-4 bg-slate-800/40 rounded-xl">
                            <div>
                                <p className="text-sm font-medium text-slate-200">Scan My Inbox Now</p>
                                <p className="text-xs text-slate-500 mt-0.5">Manually scan your most recent inbox emails on demand.</p>
                            </div>
                            <div className="flex items-center gap-2">
                                <input type="number" min={1} max={50} value={scanCount}
                                    onChange={e => setScanCount(Number(e.target.value))}
                                    className="w-16 px-2 py-1.5 bg-slate-800 border border-slate-600 rounded-lg text-sm text-slate-100 text-center focus:outline-none focus:border-blue-500" />
                                <Button variant="secondary" size="sm" loading={actionLoading === 'scan_batch'}
                                    onClick={() => act('scan_batch', () => gmailOAuthApi.scanBatch(scanCount), `Queued ${scanCount} emails for scanning.`)}>
                                    Scan
                                </Button>
                            </div>
                        </div>
                    </div>
                )}
            </Card>

            {/* Continuous Learning Panel */}
            <RetrainPanel />
        </div>
    )
}