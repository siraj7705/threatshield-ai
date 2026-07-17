import React, { useEffect, useState, useCallback } from 'react'
import { useDropzone } from 'react-dropzone'
import { emailsApi, trustedSendersApi } from '../services/api'
import { Email, FullEmailAnalysis } from '../types'
import { Card, Button, Badge, Spinner, Modal, ScoreRing, EmptyState, Table } from '../components/common'
import { formatDate, formatFileSize, severityClass, actionBadge, reputationClass, clsx, canUploadEmails, canDeleteEmails } from '../utils'
import { authStore } from '../store/auth'
import { FeedbackModal } from '../components/FeedbackModal'
import { ExportButton } from '../components/ExportButton'

function UploadZone({ onUploaded }: { onUploaded: () => void }) {
  const [uploading, setUploading] = useState(false)
  const [results, setResults] = useState<any[]>([])
  const [errors, setErrors] = useState<string[]>([])

  const onDrop = useCallback(async (accepted: File[]) => {
    if (!accepted.length) return
    setUploading(true)
    setResults([]
    )
    setErrors([])
    try {
      const res = await emailsApi.uploadBatch(accepted)
      const batchResults: any[] = res.data.results ?? []
      setResults(batchResults.filter((r: any) => r.ok))
      setErrors(batchResults.filter((r: any) => !r.ok).map((r: any) => `${r.file}: ${r.error}`))
      if (batchResults.some((r: any) => r.ok)) onUploaded()
    } catch (e: any) {
      setErrors([e.response?.data?.detail || 'Batch upload failed'])
    }
    setUploading(false)
  }, [onUploaded])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'message/rfc822': ['.eml'], 'text/plain': ['.txt'], 'application/octet-stream': ['.msg'] },
    multiple: true,
  })

  return (
    <Card className="mb-6">
      <h2 className="text-sm font-semibold text-slate-300 mb-4">Upload Emails for Analysis</h2>
      <div {...getRootProps()}
        className={clsx(
          'border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-all',
          isDragActive ? 'border-blue-500 bg-blue-500/10' : 'border-slate-600 hover:border-slate-500'
        )}>
        <input {...getInputProps()} />
        {uploading ? (
          <div className="flex flex-col items-center gap-3">
            <Spinner size="lg" />
            <p className="text-slate-400 text-sm">Analyzing emails...</p>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-2">
            <span className="text-4xl">📬</span>
            <p className="text-slate-300 font-medium">{isDragActive ? 'Drop emails here' : 'Drop emails or click to browse'}</p>
            <p className="text-slate-500 text-xs">.eml, .txt, .msg · max 25 MB each · batch upload supported</p>
          </div>
        )}
      </div>
      {results.length > 0 && (
        <div className="mt-3 flex flex-col gap-1">
          {results.map((r: any, i: number) => (
            <div key={i} className="text-xs text-green-400">
              ✓ {r.file} — score: {r.threat_score?.toFixed(0) ?? '—'}
              {r.malicious_urls?.length > 0 && (
                <span className="text-red-400 ml-2">🚨 {r.malicious_urls.length} malicious URL(s)</span>
              )}
              {r.attachments_scanned > 0 && (
                <span className={clsx('ml-2', r.attachment_threats > 0 ? 'text-red-400' : 'text-slate-500')}>
                  📎 {r.attachments_scanned} attachment{r.attachments_scanned !== 1 ? 's' : ''} scanned
                  {r.attachment_threats > 0 && ` — ${r.attachment_threats} threat(s) found`}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
      {errors.map((e, i) => (
        <p key={i} className="text-xs text-red-400 mt-1">✗ {e}</p>
      ))}
    </Card>
  )
}

function EmailDetailModal({ emailId, onClose, onDeleted }: { emailId: number; onClose: () => void; onDeleted?: () => void }) {
  const [data, setData] = useState<FullEmailAnalysis | null>(null)
  const [loading, setLoading] = useState(true)
  const [trusted, setTrusted] = useState<boolean | null>(null)
  const [trustingStatus, setTrustingStatus] = useState<'idle' | 'loading' | 'done' | 'error'>('idle')
  const [deleting, setDeleting] = useState(false)
  const [showFeedback, setShowFeedback] = useState(false)
  const canDelete = canDeleteEmails(authStore.getUser()?.role)

  useEffect(() => {
    emailsApi.get(emailId)
      .then(r => {
        setData(r.data)
        const sender = r.data.email.sender_email
        if (sender) {
          trustedSendersApi.check(sender)
            .then(res => setTrusted(res.data.trusted))
            .catch(() => setTrusted(false))
        }
      })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [emailId])

  const markTrusted = async () => {
    if (!data?.email.sender_email) return
    setTrustingStatus('loading')
    try {
      await trustedSendersApi.add(data.email.sender_email, data.email.sender_name || undefined)
      setTrusted(true)
      setTrustingStatus('done')
    } catch (e: any) {
      if (e.response?.status === 409) { setTrusted(true); setTrustingStatus('done') }
      else setTrustingStatus('error')
    }
  }

  const downloadReport = async () => {
    try {
      const res = await fetch(`/api/reports/email/${emailId}/pdf`, {
        headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
      })
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `threat-report-${emailId}.pdf`
      a.click()
    } catch { /* ignore */ }
  }

  const deleteEmail = async () => {
    if (!window.confirm('Permanently delete this email and all its analysis records? This cannot be undone.')) return
    setDeleting(true)
    try {
      await emailsApi.delete(emailId)
      onDeleted?.()
      onClose()
    } catch (e: any) {
      alert(e.response?.data?.detail || 'Failed to delete email')
      setDeleting(false)
    }
  }

  const currentLabel = data?.threat_analysis?.threat_type || 'safe'

  return (
    <>
      <Modal open onClose={onClose} title="Email Analysis Detail">
        {loading ? (
          <div className="flex justify-center py-8"><Spinner size="lg" /></div>
        ) : data ? (
          <div className="flex flex-col gap-5">
            {/* Email info */}
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="col-span-2 flex items-center justify-between">
                <div>
                  <span className="text-slate-500">From: </span>
                  <span className="text-slate-200">{data.email.sender_email || 'N/A'}</span>
                  {trusted && (
                    <span className="ml-2 text-xs text-yellow-400 bg-yellow-500/10 border border-yellow-500/20 px-1.5 py-0.5 rounded">⭐ Trusted</span>
                  )}
                </div>
                {data.email.sender_email && !trusted && (
                  <button
                    onClick={markTrusted}
                    disabled={trustingStatus === 'loading' || trustingStatus === 'done'}
                    className={clsx(
                      'flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border transition-all',
                      trustingStatus === 'done'
                        ? 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10'
                        : trustingStatus === 'error'
                          ? 'text-red-400 border-red-500/30 bg-red-500/10'
                          : 'text-slate-400 border-slate-600 hover:text-yellow-400 hover:border-yellow-500/40 hover:bg-yellow-500/5'
                    )}
                  >
                    {trustingStatus === 'loading' ? (
                      <><Spinner size="sm" /> Adding...</>
                    ) : trustingStatus === 'done' ? (
                      <>⭐ Trusted!</>
                    ) : trustingStatus === 'error' ? (
                      <>✗ Failed</>
                    ) : (
                      <>⭐ Mark as Trusted</>
                    )}
                  </button>
                )}
              </div>
              <div><span className="text-slate-500">To:</span> <span className="text-slate-200">{data.email.recipient_email || 'N/A'}</span></div>
              <div className="col-span-2"><span className="text-slate-500">Subject:</span> <span className="text-slate-200">{data.email.subject || '(no subject)'}</span></div>
              <div><span className="text-slate-500">Date:</span> <span className="text-slate-200">{formatDate(data.email.received_date)}</span></div>
              <div><span className="text-slate-500">Status:</span> <Badge label={data.email.status} /></div>
            </div>

            {/* Threat score */}
            {data.threat_score && (
              <div className="glass rounded-xl p-4 flex items-center gap-6">
                <ScoreRing score={data.threat_score.overall_score} size={90} />
                <div>
                  <p className="text-sm text-slate-400 mb-1">Threat Score</p>
                  <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs">
                    {['nlp_score', 'keyword_score', 'sender_score', 'header_score', 'urgency_score'].map(k => (
                      <div key={k} className="flex justify-between gap-3">
                        <span className="text-slate-500 capitalize">{k.replace('_score', '')}</span>
                        <span className="text-slate-300">{((data.threat_score as any)[k] * 100).toFixed(0)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Sender Reputation */}
            {data.sender_intelligence && (() => {
              const rep = data.sender_intelligence!
              return (
                <div className={clsx(
                  'rounded-xl p-4 border',
                  rep.reputation_label === 'malicious' || rep.reputation_label === 'suspicious'
                    ? 'bg-red-500/5 border-red-500/20'
                    : 'glass border-slate-700'
                )}>
                  <div className="flex items-center justify-between mb-3">
                    <p className="text-sm font-semibold text-slate-300">🕵️ Sender Reputation</p>
                    <span className={clsx('text-xs px-2 py-0.5 rounded border font-medium capitalize', reputationClass(rep.reputation_label))}>
                      {rep.reputation_label} · {rep.reputation_score.toFixed(0)}/100
                    </span>
                  </div>

                  <div className="grid grid-cols-4 gap-3 text-center mb-3">
                    <div>
                      <p className="text-slate-200 text-lg font-semibold">{rep.total_emails_seen}</p>
                      <p className="text-slate-500 text-xs">Emails seen</p>
                    </div>
                    <div>
                      <p className={clsx('text-lg font-semibold', rep.threat_emails_count > 0 ? 'text-red-400' : 'text-slate-200')}>
                        {rep.threat_emails_count}
                      </p>
                      <p className="text-slate-500 text-xs">Threats sent</p>
                    </div>
                    <div>
                      <p className="text-slate-200 text-lg font-semibold">{rep.safe_emails_count}</p>
                      <p className="text-slate-500 text-xs">Safe emails</p>
                    </div>
                    <div>
                      <p className="text-slate-200 text-lg font-semibold">{rep.avg_threat_score.toFixed(0)}</p>
                      <p className="text-slate-500 text-xs">Avg score</p>
                    </div>
                  </div>

                  {(rep.is_repeat_offender || rep.is_known_malicious || rep.domain_is_typosquat || rep.domain_is_lookalike || rep.domain_is_disposable || rep.domain_is_newly_registered) && (
                    <div className="flex flex-wrap gap-1.5 mb-2">
                      {rep.is_known_malicious && <Badge label="⚠ Known malicious" severity="critical" />}
                      {rep.is_repeat_offender && <Badge label={`🔁 Repeat offender (${rep.threat_emails_count})`} severity="high" />}
                      {rep.domain_is_typosquat && <Badge label={`Typosquat${rep.impersonated_brand ? ` of ${rep.impersonated_brand}` : ''}`} severity="high" />}
                      {rep.domain_is_lookalike && <Badge label={`Lookalike domain${rep.impersonated_brand ? ` of ${rep.impersonated_brand}` : ''}`} severity="medium" />}
                      {rep.domain_is_disposable && <Badge label="Disposable domain" severity="medium" />}
                      {rep.domain_is_newly_registered && (
                        <Badge
                          label={`🆕 Newly registered domain${rep.domain_age_days != null ? ` (${rep.domain_age_days}d old)` : ''}`}
                          severity="medium"
                        />
                      )}
                    </div>
                  )}

                  {rep.domain_age_checked && rep.domain_age_days != null && !rep.domain_is_newly_registered && (
                    <p className="text-slate-500 text-xs mb-2">
                      Domain registered {rep.domain_age_days.toLocaleString()} days ago
                      {rep.domain_registrar && ` via ${rep.domain_registrar}`}
                    </p>
                  )}

                  <p className="text-slate-500 text-xs">
                    First seen {formatDate(rep.first_seen)} · Last seen {formatDate(rep.last_seen)}
                    {rep.last_threat_at && <> · Last threat {formatDate(rep.last_threat_at)}</>}
                  </p>
                </div>
              )
            })()}


            {/* NLP Analysis */}
            {data.threat_analysis && data.threat_analysis.threat_detected && (
              <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-red-400 font-semibold text-sm">⚠ Threat Detected</span>
                  <Badge label={data.threat_analysis.severity} severity={data.threat_analysis.severity} />
                  <Badge label={data.threat_analysis.threat_type || ''} />
                </div>
                {data.threat_analysis.threat_description && (
                  <p className="text-slate-400 text-xs">{data.threat_analysis.threat_description}</p>
                )}
                {data.threat_analysis.keywords_found && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {JSON.parse(data.threat_analysis.keywords_found).slice(0, 10).map((k: string) => (
                      <span key={k} className="text-xs bg-red-500/10 text-red-400 border border-red-500/20 rounded px-1.5 py-0.5">{k}</span>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Header analysis */}
            {data.header_analysis && (
              <div className="glass rounded-xl p-4">
                <p className="text-sm font-semibold text-slate-300 mb-2">Header Forensics</p>
                <div className="grid grid-cols-3 gap-2 text-xs">
                  <div className="text-center">
                    <p className="text-slate-500">SPF</p>
                    <Badge label={data.header_analysis.spf_result || 'N/A'} />
                  </div>
                  <div className="text-center">
                    <p className="text-slate-500">DKIM</p>
                    <Badge label={data.header_analysis.dkim_result || 'N/A'} />
                  </div>
                  <div className="text-center">
                    <p className="text-slate-500">DMARC</p>
                    <Badge label={data.header_analysis.dmarc_result || 'N/A'} />
                  </div>
                </div>
                {data.header_analysis.spoofing_detected && (
                  <p className="text-red-400 text-xs mt-2">⚠ Spoofing detected</p>
                )}
                {data.header_analysis.originating_ip && (
                  <p className="text-slate-500 text-xs mt-1">Origin IP: <span className="text-slate-300 font-mono">{data.header_analysis.originating_ip}</span>
                    {data.header_analysis.originating_country && ` (${data.header_analysis.originating_country})`}
                  </p>
                )}
              </div>
            )}

            {/* IP Reputation — VPN / Tor / Proxy detection */}
            {data.ip_reputation && data.ip_reputation.checked && (() => {
              const rep = data.ip_reputation!
              const reasons: string[] = rep.risk_reasons ? JSON.parse(rep.risk_reasons) : []
              const flagged = rep.is_vpn || rep.is_tor || rep.is_proxy || rep.is_hosting
              return (
                <div className={clsx(
                  'rounded-xl p-4 border',
                  rep.is_tor || rep.is_proxy ? 'bg-red-500/5 border-red-500/30' :
                    rep.is_vpn ? 'bg-orange-500/5 border-orange-500/20' :
                      'glass border-slate-700'
                )}>
                  <div className="flex items-center justify-between mb-3">
                    <p className="text-sm font-semibold text-slate-300">🌐 IP Reputation</p>
                    {rep.ip_risk_score > 0 && (
                      <span className={clsx(
                        'text-xs px-2 py-0.5 rounded border font-medium',
                        rep.ip_risk_score >= 70 ? 'text-red-400 border-red-500/30 bg-red-500/10' :
                          rep.ip_risk_score >= 40 ? 'text-orange-400 border-orange-500/30 bg-orange-500/10' :
                            'text-yellow-400 border-yellow-500/30 bg-yellow-500/10'
                      )}>
                        Risk {rep.ip_risk_score.toFixed(0)}/100
                      </span>
                    )}
                  </div>

                  <div className="flex flex-wrap gap-1.5 mb-2">
                    {rep.is_tor && <Badge label="🧅 Tor exit node" severity="critical" />}
                    {rep.is_proxy && <Badge label="🛡 Open proxy" severity="high" />}
                    {rep.is_vpn && <Badge label="🔒 VPN endpoint" severity="medium" />}
                    {rep.is_hosting && !rep.is_vpn && !rep.is_tor && <Badge label="☁ Datacenter / hosting IP" severity="low" />}
                    {!flagged && <Badge label="✓ Residential / ISP IP" />}
                  </div>

                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-slate-400">
                    <p><span className="text-slate-500">IP:</span> <span className="font-mono text-slate-300">{rep.ip}</span></p>
                    {rep.isp && <p><span className="text-slate-500">ISP:</span> {rep.isp}</p>}
                    {rep.org && <p><span className="text-slate-500">Org:</span> {rep.org}</p>}
                    {(rep.city || rep.country) && (
                      <p><span className="text-slate-500">Location:</span> {[rep.city, rep.country].filter(Boolean).join(', ')}</p>
                    )}
                  </div>

                  {reasons.length > 0 && (
                    <ul className="mt-2 flex flex-col gap-0.5">
                      {reasons.map((r, i) => (
                        <li key={i} className="text-xs text-slate-500">• {r}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )
            })()}

            {/* URL Analysis */}
            {data.url_analysis && (() => {
              const urls: string[] = JSON.parse(data.url_analysis.urls_found || '[]')
              const malicious: string[] = JSON.parse(data.url_analysis.malicious_urls || '[]')
              const suspicious: string[] = JSON.parse(data.url_analysis.suspicious_urls || '[]')
              const details: { url: string; domain: string; risk: string; reasons: string[] }[] =
                JSON.parse(data.url_analysis.analysis_details || '[]')
              const threatTypes: string[] = JSON.parse(data.url_analysis.url_threat_types || '[]')

              if (urls.length === 0) return null

              return (
                <div className={clsx(
                  'rounded-xl p-4 border',
                  malicious.length > 0
                    ? 'bg-red-500/5 border-red-500/30'
                    : suspicious.length > 0
                      ? 'bg-yellow-500/5 border-yellow-500/30'
                      : 'glass border-slate-700'
                )}>
                  <div className="flex items-center justify-between mb-3">
                    <p className="text-sm font-semibold text-slate-300">🔗 Link Analysis</p>
                    <div className="flex items-center gap-2 text-xs">
                      <span className="text-slate-500">{urls.length} link{urls.length !== 1 ? 's' : ''}</span>
                      {data.url_analysis.safe_browsing_checked && (
                        <span className="text-green-500/70">✓ Google Safe Browsing</span>
                      )}
                      {data.url_analysis.url_risk_score > 0 && (
                        <span className={clsx(
                          'px-1.5 py-0.5 rounded border font-medium',
                          data.url_analysis.url_risk_score >= 70 ? 'text-red-400 border-red-500/30 bg-red-500/10' :
                            data.url_analysis.url_risk_score >= 35 ? 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10' :
                              'text-green-400 border-green-500/30 bg-green-500/10'
                        )}>
                          Risk {data.url_analysis.url_risk_score.toFixed(0)}/100
                        </span>
                      )}
                    </div>
                  </div>

                  {malicious.length > 0 && (
                    <div className="mb-3 bg-red-500/10 rounded-lg p-2">
                      <p className="text-red-400 text-xs font-semibold mb-1">
                        🚨 {malicious.length} MALICIOUS URL{malicious.length > 1 ? 'S' : ''} DETECTED
                      </p>
                      {threatTypes.length > 0 && (
                        <p className="text-red-300 text-xs">Threat types: {threatTypes.join(', ')}</p>
                      )}
                      {malicious.map((url, i) => (
                        <p key={i} className="text-red-300 font-mono text-xs mt-1 break-all">{url}</p>
                      ))}
                    </div>
                  )}

                  <div className="flex flex-col gap-1.5 max-h-48 overflow-y-auto">
                    {details.map((d, i) => (
                      <div key={i} className={clsx(
                        'rounded-lg px-3 py-2 border text-xs',
                        d.risk === 'malicious' ? 'bg-red-500/10 border-red-500/20' :
                          d.risk === 'suspicious' ? 'bg-yellow-500/10 border-yellow-500/20' :
                            'bg-slate-800/40 border-slate-700/50'
                      )}>
                        <div className="flex items-center gap-2 mb-0.5">
                          <span>{d.risk === 'malicious' ? '🚨' : d.risk === 'suspicious' ? '⚠️' : '✅'}</span>
                          <span className={clsx(
                            'font-mono break-all',
                            d.risk === 'malicious' ? 'text-red-300' :
                              d.risk === 'suspicious' ? 'text-yellow-300' :
                                'text-slate-300'
                          )}>{d.url}</span>
                        </div>
                        {d.reasons.length > 0 && (
                          <p className="text-slate-500 mt-0.5 pl-5">{d.reasons.join(' · ')}</p>
                        )}
                      </div>
                    ))}
                  </div>

                  {data.url_analysis.domain_age_checked_url && data.url_analysis.domain_age_days != null && (
                    <p className={clsx(
                      'text-xs mt-2 pt-2 border-t border-slate-700/50',
                      data.url_analysis.domain_is_newly_registered ? 'text-orange-400' : 'text-slate-500'
                    )}>
                      {data.url_analysis.domain_is_newly_registered ? '🆕 ' : ''}
                      Link domain registered {data.url_analysis.domain_age_days.toLocaleString()} day{data.url_analysis.domain_age_days !== 1 ? 's' : ''} ago
                      {data.url_analysis.domain_is_newly_registered && ' — newly registered domains are a common phishing signal'}
                    </p>
                  )}
                </div>
              )
            })()}

            {/* Attachment Scan Results */}
            {data.attachment_scans && data.attachment_scans.length > 0 && (() => {
              const scans = data.attachment_scans!
              const anyThreat = scans.some(s => s.threat_detected)
              const topRisk = Math.max(...scans.map(s => s.attachment_risk_score), 0)
              return (
                <div className={clsx(
                  'rounded-xl p-4 border',
                  anyThreat ? 'bg-red-500/5 border-red-500/30' : 'glass border-slate-700'
                )}>
                  <div className="flex items-center justify-between mb-3">
                    <p className="text-sm font-semibold text-slate-300">📎 Attachment Scan Results</p>
                    <div className="flex items-center gap-2 text-xs">
                      <span className="text-slate-500">{scans.length} file{scans.length !== 1 ? 's' : ''} scanned</span>
                      {topRisk > 0 && (
                        <span className={clsx(
                          'px-1.5 py-0.5 rounded border font-medium',
                          topRisk >= 70 ? 'text-red-400 border-red-500/30 bg-red-500/10' :
                            topRisk >= 35 ? 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10' :
                              'text-green-400 border-green-500/30 bg-green-500/10'
                        )}>
                          Risk {topRisk.toFixed(0)}/100
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="flex flex-col gap-2">
                    {scans.map((s) => {
                      const keywords: string[] = s.keywords_found ? JSON.parse(s.keywords_found) : []
                      const reasons: string[] = s.risk_reasons ? JSON.parse(s.risk_reasons) : []
                      return (
                        <div key={s.id} className={clsx(
                          'rounded-lg px-3 py-2.5 border text-xs',
                          s.threat_detected ? 'bg-red-500/10 border-red-500/20' : 'bg-slate-800/40 border-slate-700/50'
                        )}>
                          <div className="flex items-center gap-2 mb-1">
                            <span>{s.threat_detected ? '🚨' : s.extraction_ok ? '✅' : '❔'}</span>
                            <span className="font-mono text-slate-300 break-all">{s.filename || 'unnamed'}</span>
                            {s.content_type && <span className="text-slate-500">({s.content_type})</span>}
                            {s.file_size != null && <span className="text-slate-500">· {formatFileSize(s.file_size)}</span>}
                          </div>

                          {!s.extraction_ok ? (
                            <p className="text-slate-500 pl-5">
                              {s.extraction_error || 'Could not extract text from this attachment'}
                            </p>
                          ) : s.threat_detected ? (
                            <div className="pl-5 flex flex-col gap-1">
                              <p className="text-red-300">
                                {s.threat_type} detected — confidence {(s.confidence_score * 100).toFixed(0)}%
                                {s.attachment_risk_score > 0 && <> · risk {s.attachment_risk_score.toFixed(0)}/100</>}
                              </p>
                              {s.threat_description && <p className="text-slate-400">{s.threat_description}</p>}
                              {keywords.length > 0 && (
                                <div className="flex flex-wrap gap-1 mt-0.5">
                                  {keywords.slice(0, 8).map((k) => (
                                    <span key={k} className="text-xs bg-red-500/10 text-red-400 border border-red-500/20 rounded px-1.5 py-0.5">{k}</span>
                                  ))}
                                </div>
                              )}
                              {reasons.length > 0 && <p className="text-slate-500">{reasons.join(' · ')}</p>}
                            </div>
                          ) : (
                            <p className="text-slate-500 pl-5">No threat content found ({s.extraction_method})</p>
                          )}
                        </div>
                      )
                    })}
                  </div>
                </div>
              )
            })()}

            {/* Body preview */}
            {data.email.body_text && (
              <div>
                <p className="text-xs text-slate-500 mb-1">Email Body Preview</p>
                <pre className="text-xs text-slate-400 bg-slate-800/50 rounded-lg p-3 max-h-40 overflow-y-auto whitespace-pre-wrap font-mono">
                  {data.email.body_text.slice(0, 1000)}{data.email.body_text.length > 1000 ? '...' : ''}
                </pre>
              </div>
            )}

            <div className="flex items-center gap-2 flex-wrap">
              <Button onClick={downloadReport} variant="secondary" size="sm">📄 Download PDF Report</Button>
              <Button onClick={() => setShowFeedback(true)} variant="secondary" size="sm">
                🧠 Correct Prediction
              </Button>
              {canDelete && (
                <Button onClick={deleteEmail} variant="danger" size="sm" loading={deleting}>
                  🗑️ Delete Email
                </Button>
              )}
            </div>
          </div>
        ) : (
          <EmptyState icon="❌" title="Failed to load email details" />
        )}
      </Modal>

      {showFeedback && (
        <FeedbackModal
          emailId={emailId}
          currentLabel={currentLabel}
          onClose={() => setShowFeedback(false)}
          onSubmitted={() => setShowFeedback(false)}
        />
      )}
    </>
  )
}

export default function EmailsPage() {
  const [emails, setEmails] = useState<Email[]>([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<number | null>(null)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [trustedEmails, setTrustedEmails] = useState<Set<string>>(new Set())
  const [trustingId, setTrustingId] = useState<number | null>(null)
  const role = authStore.getUser()?.role
  const canUpload = canUploadEmails(role)

  const loadTrusted = () => {
    trustedSendersApi.list()
      .then(r => setTrustedEmails(new Set(r.data.map((t: any) => t.email.toLowerCase()))))
      .catch(() => { })
  }

  const quickTrust = async (e: React.MouseEvent, email: Email) => {
    e.stopPropagation()
    if (!email.sender_email) return
    setTrustingId(email.id)
    try {
      await trustedSendersApi.add(email.sender_email)
      setTrustedEmails(prev => new Set([...prev, email.sender_email!.toLowerCase()]))
    } catch { /* 409 = already trusted, ignore */ }
    finally { setTrustingId(null) }
  }

  const isTrusted = (senderEmail?: string) => {
    if (!senderEmail) return false
    const lower = senderEmail.toLowerCase()
    if (trustedEmails.has(lower)) return true
    const domain = '@' + lower.split('@')[1]
    return trustedEmails.has(domain)
  }

  const load = () => {
    setLoading(true)
    emailsApi.list({ page, per_page: 20 })
      .then(r => { setEmails(r.data.emails); setTotal(r.data.total) })
      .catch(console.error)
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [page])
  useEffect(() => { loadTrusted() }, [])

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Emails</h1>
          <p className="text-slate-400 text-sm mt-1">Upload and analyze suspicious emails</p>
        </div>
        <ExportButton entity="emails" />
      </div>

      {canUpload ? (
        <UploadZone onUploaded={load} />
      ) : (
        <Card className="mb-6">
          <p className="text-slate-400 text-sm">
            🔒 Your role (<span className="capitalize">{role}</span>) is read-only. Ask an admin or analyst to upload emails for analysis.
          </p>
        </Card>
      )}

      <Card>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-slate-300">Email Queue <span className="text-slate-500 font-normal">({total} total)</span></h2>
        </div>

        {loading ? (
          <div className="flex justify-center py-8"><Spinner /></div>
        ) : emails.length === 0 ? (
          <EmptyState icon="📬" title="No emails yet" message="Upload some emails to get started" />
        ) : (
          <Table headers={['Subject', 'From', 'Date', 'Status', 'Action', '']}>
            {emails.map(email => (
              <tr key={email.id} className="hover:bg-slate-800/30 transition-colors group">
                <td className="py-3 px-4 text-sm text-slate-200 max-w-xs truncate">{email.subject || '(no subject)'}</td>
                <td className="py-3 px-4 text-sm text-slate-400 max-w-xs">
                  <div className="flex items-center gap-1.5 truncate">
                    {isTrusted(email.sender_email) && (
                      <span title="Trusted sender" className="text-yellow-400 flex-shrink-0">⭐</span>
                    )}
                    <span className="truncate">{email.sender_email || 'N/A'}</span>
                    {!isTrusted(email.sender_email) && email.sender_email && (
                      <button
                        onClick={(e) => quickTrust(e, email)}
                        disabled={trustingId === email.id}
                        title="Mark sender as trusted"
                        className="flex-shrink-0 opacity-0 group-hover:opacity-100 text-xs text-slate-500 hover:text-yellow-400 transition-all px-1"
                      >
                        {trustingId === email.id ? '...' : '⭐'}
                      </button>
                    )}
                  </div>
                </td>
                <td className="py-3 px-4 text-xs text-slate-500 whitespace-nowrap">{formatDate(email.upload_date)}</td>
                <td className="py-3 px-4"><Badge label={email.status} /></td>
                <td className="py-3 px-4">
                  <span className={clsx('text-xs px-2 py-0.5 rounded border', actionBadge(email.action_taken))}>
                    {email.action_taken}
                  </span>
                </td>
                <td className="py-3 px-4">
                  <Button variant="ghost" size="sm" onClick={() => setSelected(email.id)}>View →</Button>
                </td>
              </tr>
            ))}
          </Table>
        )}

        {total > 20 && (
          <div className="flex justify-center gap-2 mt-4">
            <Button variant="secondary" size="sm" disabled={page === 1} onClick={() => setPage(p => p - 1)}>Prev</Button>
            <span className="text-slate-400 text-sm flex items-center">Page {page}</span>
            <Button variant="secondary" size="sm" disabled={page * 20 >= total} onClick={() => setPage(p => p + 1)}>Next</Button>
          </div>
        )}
      </Card>

      {selected && <EmailDetailModal emailId={selected} onClose={() => setSelected(null)} onDeleted={load} />}
    </div>
  )
}