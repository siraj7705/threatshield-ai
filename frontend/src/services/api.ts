import axios from 'axios'

// In Docker, VITE_API_URL is set to "" so axios uses relative paths
// (nginx proxies /api -> backend). In local dev without Docker, it's
// unset, so we fall back to the dev backend on localhost:8000.
const envUrl = import.meta.env.VITE_API_URL
const BASE_URL = envUrl !== undefined ? envUrl : 'http://localhost:8000'

export const api = axios.create({
  baseURL: BASE_URL,
  headers: { 'Content-Type': 'application/json' },
})

// Attach token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Handle 401
api.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// Auth
export const authApi = {
  login: (username: string, password: string) =>
    api.post('/api/auth/login', { username, password }),
  register: (data: { username: string; email: string; password: string; full_name?: string; role?: string }) =>
    api.post('/api/auth/register', data),
  me: () => api.get('/api/auth/me'),
}

// Emails
export const emailsApi = {
  upload: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return api.post('/api/emails/upload', form, { headers: { 'Content-Type': 'multipart/form-data' } })
  },
  /** Upload multiple files in a single request. Returns 207 with per-file results. */
  uploadBatch: (files: File[]) => {
    const form = new FormData()
    files.forEach(f => form.append('files', f))
    return api.post('/api/emails/upload-batch', form, { headers: { 'Content-Type': 'multipart/form-data' } })
  },
  list: (params?: { page?: number; per_page?: number; status?: string }) =>
    api.get('/api/emails', { params }),
  get: (id: number) => api.get(`/api/emails/${id}`),
  delete: (id: number) => api.delete(`/api/emails/${id}`),
}

// Dashboard
export const dashboardApi = {
  stats: (days?: number) => api.get('/api/dashboard/stats', { params: { days } }),
  topThreatDomains: (limit = 10, days?: number) => api.get('/api/dashboard/top-threat-domains', { params: { limit, days } }),
  timeline: (days?: number, threat_type?: string) => api.get('/api/dashboard/timeline', { params: { days, threat_type } }),
  locationMap: (days?: number) => api.get('/api/dashboard/location-map', { params: { days } }),
}

// Alerts
export const alertsApi = {
  list: (params?: { severity?: string; acknowledged?: boolean; page?: number; per_page?: number }) =>
    api.get('/api/alerts', { params }),
  acknowledge: (id: number) => api.put(`/api/alerts/${id}/acknowledge`),
  unacknowledgedCount: () => api.get('/api/alerts/unacknowledged/count'),
}

// Cases
export const casesApi = {
  list: (params?: { status?: string; priority?: string; page?: number; per_page?: number }) =>
    api.get('/api/cases', { params }),
  get: (id: number) => api.get(`/api/cases/${id}`),
  create: (data: { title: string; description?: string; priority?: string; email_ids?: number[] }) =>
    api.post('/api/cases', data),
  updateStatus: (id: number, status: string) =>
    api.put(`/api/cases/${id}/status`, { status }),
  addNote: (id: number, note: string) =>
    api.post(`/api/cases/${id}/notes`, { note }),
  delete: (id: number) => api.delete(`/api/cases/${id}`),
}

// Reports
export const reportsApi = {
  emailPdf: (emailId: number) =>
    api.get(`/api/reports/email/${emailId}/pdf`, { responseType: 'blob' }),
  summary: () => api.get('/api/reports/summary'),
}

// Trusted Senders
export const trustedSendersApi = {
  list: () => api.get('/api/trusted-senders'),
  add: (email: string, name?: string) =>
    api.post('/api/trusted-senders', { email, name }),
  remove: (id: number) => api.delete(`/api/trusted-senders/${id}`),
  check: (email: string) =>
    api.get('/api/trusted-senders/check', { params: { email } }),
}

// Feedback & Continuous Learning
export const feedbackApi = {
  submit: (emailId: number, correctLabel: string, notes?: string) =>
    api.post('/api/feedback', { email_id: emailId, correct_label: correctLabel, notes }),
  status: () => api.get('/api/feedback/status'),
  history: () => api.get('/api/feedback/history'),
  retrain: (minSamples: number = 5) =>
    api.post('/api/feedback/retrain', { min_samples: minSamples }),
}

// Cross-entity search
export const searchApi = {
  search: (params: { q: string; entity?: string; page?: number; per_page?: number }) =>
    api.get('/api/search', { params }),
}

// CSV export — browser downloads via window.open or a blob fetch
export const exportApi = {
  emailsCsv: (params?: { status?: string; action?: string }) =>
    api.get('/api/export/emails.csv', { params, responseType: 'blob' }),
  threatsCsv: (params?: { threat_type?: string; severity?: string }) =>
    api.get('/api/export/threats.csv', { params, responseType: 'blob' }),
  alertsCsv: (params?: { severity?: string; acknowledged?: boolean }) =>
    api.get('/api/export/alerts.csv', { params, responseType: 'blob' }),
}

/** Trigger a browser download from a blob response */
export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

// Gmail OAuth — per-user connected Gmail account (separate from the legacy
// admin-only shared-mailbox controls on /gmail, see gmailApi-style calls
// inline in GmailPage.tsx).
export const gmailOAuthApi = {
  // Returns { authorization_url } — caller should do
  // window.location.href = authorization_url to hand off to Google's
  // consent screen. This is a real browser navigation, not an XHR/fetch,
  // because Google's redirect back to /oauth/callback can't carry our
  // Authorization header.
  connect: () => api.get('/api/gmail/oauth/connect'),
  status: () => api.get('/api/gmail/oauth/status'),
  disconnect: () => api.delete('/api/gmail/oauth/disconnect'),
  scanOne: (gmailId: string) => api.post(`/api/gmail/oauth/scan/${gmailId}`),
  scanBatch: (maxEmails: number = 10) =>
    api.post(`/api/gmail/oauth/scan/batch`, null, { params: { max_emails: maxEmails } }),
  watchStart: () => api.post('/api/gmail/oauth/watch/start'),
  watchStop: () => api.post('/api/gmail/oauth/watch/stop'),
}
// Graph Analysis
export const graphApi = {
  build: (days = 90, threatOnly = true) => api.get('/api/graph/build', { params: { days, threat_only: threatOnly } }),
  clusters: (days = 90) => api.get('/api/graph/clusters', { params: { days } }),
  central: (days = 90, topN = 10) => api.get('/api/graph/central-nodes', { params: { days, top_n: topN } }),
  paths: (source: string, target: string, days = 90) => api.get('/api/graph/paths', { params: { source, target, days } }),
  coOccurrence: (days = 90) => api.get('/api/graph/co-occurrence', { params: { days } }),
}