export interface User {
  id: number
  username: string
  email: string
  full_name?: string
  role: 'admin' | 'analyst' | 'investigator'
  is_active: boolean
  created_at?: string
  last_login?: string
}

export interface TokenResponse {
  access_token: string
  refresh_token: string
  token_type: string
  user: User
}

export interface Email {
  id: number
  message_id?: string
  subject?: string
  sender_email?: string
  sender_name?: string
  recipient_email?: string
  body_text?: string
  received_date?: string
  upload_date?: string
  source_type: string
  file_name?: string
  file_size?: number
  status: string
  action_taken: string
}

export interface ThreatAnalysis {
  id: number
  email_id: number
  threat_detected: boolean
  threat_type?: string
  threat_target?: string
  threat_description?: string
  confidence_score: number
  severity: string
  intent_score: number
  urgency_score: number
  keywords_found?: string
  entities_found?: string
  nlp_model_used?: string
  analysis_duration_ms?: number
  analyzed_at?: string
}

export interface ThreatScore {
  id: number
  email_id: number
  overall_score: number
  nlp_score: number
  keyword_score: number
  sender_score: number
  header_score: number
  urgency_score: number
  attachment_score: number
  category: string
  explanation?: string
  recommended_action: string
  scored_at?: string
}

export interface HeaderAnalysis {
  id: number
  email_id: number
  return_path?: string
  originating_ip?: string
  originating_country?: string
  spf_result?: string
  dkim_result?: string
  dmarc_result?: string
  spoofing_detected: boolean
  header_risk_score: number
  from_domain?: string
  domain_match?: boolean
  analyzed_at?: string
}

export interface URLAnalysisDetail {
  url: string
  domain: string
  risk: 'safe' | 'suspicious' | 'malicious'
  reasons: string[]
}

export interface URLAnalysis {
  id: number
  email_id: number
  urls_found?: string        // JSON array string
  malicious_urls?: string    // JSON array string
  suspicious_urls?: string   // JSON array string
  url_risk_score: number
  url_threat_types?: string  // JSON array string
  safe_browsing_checked: boolean
  analysis_details?: string  // JSON array string
  domain_age_checked_url?: string
  domain_age_days?: number
  domain_is_newly_registered?: boolean
  analyzed_at?: string
}

export interface AttachmentScan {
  id: number
  email_id: number
  filename?: string
  content_type?: string
  file_size?: number

  extraction_ok: boolean
  extraction_method?: string
  extraction_error?: string
  extracted_text_preview?: string

  threat_detected: boolean
  threat_type?: string
  threat_target?: string
  threat_description?: string
  confidence_score: number
  severity: string
  intent_score: number
  urgency_score: number
  keywords_found?: string   // JSON array string

  attachment_risk_score: number
  risk_reasons?: string     // JSON array string

  scanned_at?: string
}

export interface SenderIntelligence {
  id: number
  sender_email: string
  sender_domain: string

  total_emails_seen: number
  threat_emails_count: number
  safe_emails_count: number
  blocked_count: number
  quarantined_count: number

  avg_threat_score: number
  max_threat_score: number
  last_threat_score: number

  reputation_score: number
  reputation_label: 'trusted' | 'clean' | 'neutral' | 'suspicious' | 'malicious' | 'unknown'

  is_known_malicious: boolean
  is_repeat_offender: boolean
  is_trusted: boolean

  domain_is_disposable: boolean
  domain_is_typosquat: boolean
  domain_is_lookalike: boolean
  domain_is_suspicious_tld: boolean
  impersonated_brand?: string

  domain_age_checked?: boolean
  domain_registered_at?: string
  domain_age_days?: number
  domain_is_newly_registered?: boolean
  domain_registrar?: string

  first_seen?: string
  last_seen?: string
  last_threat_at?: string

  notes?: string
}

export interface IPReputation {
  id: number
  email_id: number
  ip?: string
  checked: boolean

  is_vpn: boolean
  is_tor: boolean
  is_proxy: boolean
  is_hosting: boolean

  isp?: string
  org?: string
  country?: string
  city?: string

  ip_risk_score: number
  risk_reasons?: string   // JSON array string
  error?: string

  checked_at?: string
}

export interface FullEmailAnalysis {
  email: Email
  threat_analysis?: ThreatAnalysis
  threat_score?: ThreatScore
  header_analysis?: HeaderAnalysis
  url_analysis?: URLAnalysis
  attachment_scans?: AttachmentScan[]
  sender_intelligence?: SenderIntelligence | null
  ip_reputation?: IPReputation | null
}

export interface Alert {
  id: number
  email_id?: number
  alert_type: string
  severity: string
  title: string
  message: string
  details?: string
  is_acknowledged: boolean
  acknowledged_by?: number
  acknowledged_at?: string
  created_at?: string
}

export interface Case {
  id: number
  case_number: string
  title: string
  description?: string
  status: string
  priority: string
  assigned_to?: number
  created_by?: number
  email_ids?: string
  notes?: string
  created_at?: string
  updated_at?: string
  closed_at?: string
}

export interface DashboardStats {
  total_emails: number
  threat_emails: number
  safe_emails: number
  blocked_emails: number
  quarantined_emails: number
  pending_emails: number
  critical_alerts: number
  unacknowledged_alerts: number
  active_cases: number
}

export interface DashboardData {
  stats: DashboardStats
  recent_alerts: Alert[]
  threat_trends: { date: string; count: number }[]
  severity_distribution: Record<string, number>
  top_threat_types: Record<string, number>
}

export interface TrustedSender {
  id: number
  user_id: number
  email: string
  name?: string
  added_at?: string
}

export interface GmailAccount {
  id: number
  gmail_address: string
  is_active: boolean
  is_watching: boolean
  last_synced_at?: string | null
  last_error?: string | null
  connected_at?: string | null
}