import { formatDistanceToNow, format } from 'date-fns'
import clsx from 'clsx'

export { clsx }

export function formatDate(date?: string | null) {
  if (!date) return 'N/A'
  try {
    return format(new Date(date), 'MMM d, yyyy HH:mm')
  } catch {
    return date
  }
}

export function timeAgo(date?: string | null) {
  if (!date) return 'N/A'
  try {
    return formatDistanceToNow(new Date(date), { addSuffix: true })
  } catch {
    return date
  }
}

export function severityClass(severity: string): string {
  const map: Record<string, string> = {
    critical: 'severity-critical',
    high_risk: 'severity-high',
    high: 'severity-high',
    suspicious: 'severity-medium',
    medium: 'severity-medium',
    low: 'severity-low',
    safe: 'severity-safe',
    clean: 'severity-safe',
  }
  return map[severity?.toLowerCase()] || 'severity-safe'
}

export function severityColor(severity: string): string {
  const map: Record<string, string> = {
    critical: '#ef4444',
    high_risk: '#ea580c',
    high: '#f97316',
    suspicious: '#eab308',
    medium: '#eab308',
    low: '#3b82f6',
    safe: '#22c55e',
    clean: '#22c55e',
  }
  // Default to a distinct gray instead of safe green for unknown severities
  return map[severity?.toLowerCase()] || '#94a3b8'
}

export function scoreToCategory(score: number): string {
  if (score >= 81) return 'critical'
  if (score >= 61) return 'high'
  if (score >= 31) return 'medium'
  return 'safe'
}

export function actionBadge(action: string) {
  const map: Record<string, string> = {
    block: 'text-red-400 bg-red-500/10 border-red-500/30',
    quarantine: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    allow: 'text-green-400 bg-green-500/10 border-green-500/30',
    none: 'text-slate-400 bg-slate-500/10 border-slate-500/30',
  }
  return map[action] || map['none']
}

export function formatFileSize(bytes?: number): string {
  if (!bytes) return 'N/A'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function reputationClass(label: string): string {
  const map: Record<string, string> = {
    malicious: 'text-red-400 bg-red-500/10 border-red-500/30',
    suspicious: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    neutral: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
    clean: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
    trusted: 'text-green-400 bg-green-500/10 border-green-500/30',
    unknown: 'text-slate-400 bg-slate-500/10 border-slate-500/30',
  }
  return map[label?.toLowerCase()] || map['unknown']
}

// ── Permission helpers ──────────────────────────────────────────────
// Mirrors the role model enforced server-side in backend/app/core/security.py:
//   Admin        → full access: manage users, delete emails, change settings
//   Analyst      → analyze emails, manage alerts, create cases, generate reports
//   Investigator → read-only + case notes, cannot upload/delete emails
//
// These checks are UX only — hiding/disabling actions an investigator
// can't perform anyway. The backend re-checks on every request and is
// the actual source of truth; never rely on this for security.
export type Role = 'admin' | 'analyst' | 'investigator'

export function canUploadEmails(role?: string): boolean {
  return role === 'admin' || role === 'analyst'
}

export function canDeleteEmails(role?: string): boolean {
  return role === 'admin'
}

export function canManageAlerts(role?: string): boolean {
  return role === 'admin' || role === 'analyst'
}

export function canManageCases(role?: string): boolean {
  return role === 'admin' || role === 'analyst'
}

export function canDeleteCases(role?: string): boolean {
  return role === 'admin'
}

export function canManageGmailWatch(role?: string): boolean {
  return role === 'admin'
}

export function canTriggerGmailScan(role?: string): boolean {
  return role === 'admin' || role === 'analyst'
}