-- ThreatShield AI - Database Schema
-- Compatible with PostgreSQL and SQLite

-- ============================================
-- USERS & AUTHENTICATION
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    role VARCHAR(20) NOT NULL DEFAULT 'analyst',  -- admin, analyst, investigator
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- ============================================
-- EMAILS
-- ============================================
CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id VARCHAR(500),
    subject TEXT,
    sender_email VARCHAR(255),
    sender_name VARCHAR(255),
    recipient_email TEXT,
    cc_emails TEXT,
    bcc_emails TEXT,
    body_text TEXT,
    body_html TEXT,
    raw_headers TEXT,
    raw_content TEXT,
    received_date TIMESTAMP,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    uploaded_by INTEGER REFERENCES users(id),
    source_type VARCHAR(20) DEFAULT 'upload',  -- upload, smtp, stream
    file_name VARCHAR(255),
    file_size INTEGER,
    status VARCHAR(20) DEFAULT 'pending',  -- pending, analyzing, analyzed, error
    action_taken VARCHAR(20) DEFAULT 'none'  -- none, allow, spam, quarantine, block, delete
);

-- ============================================
-- THREAT ANALYSIS
-- ============================================
CREATE TABLE IF NOT EXISTS threat_analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    threat_detected BOOLEAN DEFAULT FALSE,
    threat_type VARCHAR(50),  -- bomb_threat, violence, terror, extortion, harassment, safe
    threat_target TEXT,
    threat_description TEXT,
    confidence_score REAL DEFAULT 0.0,
    severity VARCHAR(20) DEFAULT 'safe',  -- safe, low, medium, high, critical
    intent_score REAL DEFAULT 0.0,
    urgency_score REAL DEFAULT 0.0,
    keywords_found TEXT,  -- JSON array of detected keywords
    entities_found TEXT,  -- JSON array of NER entities
    nlp_model_used VARCHAR(100),
    analysis_duration_ms INTEGER,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- HEADER ANALYSIS
-- ============================================
CREATE TABLE IF NOT EXISTS header_analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    return_path VARCHAR(255),
    received_chain TEXT,  -- JSON array of received headers
    originating_ip VARCHAR(45),
    originating_country VARCHAR(100),
    originating_city VARCHAR(100),
    spf_result VARCHAR(20),  -- pass, fail, softfail, none
    dkim_result VARCHAR(20),  -- pass, fail, none
    dmarc_result VARCHAR(20),  -- pass, fail, none
    message_id_valid BOOLEAN,
    from_domain VARCHAR(255),
    return_path_domain VARCHAR(255),
    domain_match BOOLEAN,
    spoofing_detected BOOLEAN DEFAULT FALSE,
    routing_anomalies TEXT,  -- JSON array of anomalies
    mail_client VARCHAR(255),
    header_risk_score REAL DEFAULT 0.0,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- SENDER INTELLIGENCE
-- ============================================
CREATE TABLE IF NOT EXISTS sender_intelligence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    sender_email VARCHAR(255),
    sender_domain VARCHAR(255),
    is_disposable_email BOOLEAN DEFAULT FALSE,
    domain_age_days INTEGER,
    domain_registered_date TIMESTAMP,
    is_newly_registered BOOLEAN DEFAULT FALSE,
    is_blacklisted BOOLEAN DEFAULT FALSE,
    domain_reputation_score REAL DEFAULT 50.0,
    ip_address VARCHAR(45),
    ip_reputation_score REAL DEFAULT 50.0,
    is_tor_exit_node BOOLEAN DEFAULT FALSE,
    is_vpn BOOLEAN DEFAULT FALSE,
    is_proxy BOOLEAN DEFAULT FALSE,
    hosting_provider VARCHAR(255),
    overall_sender_score REAL DEFAULT 50.0,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- THREAT SCORES
-- ============================================
CREATE TABLE IF NOT EXISTS threat_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    overall_score REAL NOT NULL DEFAULT 0.0,
    nlp_score REAL DEFAULT 0.0,
    keyword_score REAL DEFAULT 0.0,
    sender_score REAL DEFAULT 0.0,
    header_score REAL DEFAULT 0.0,
    urgency_score REAL DEFAULT 0.0,
    attachment_score REAL DEFAULT 0.0,
    category VARCHAR(20) NOT NULL DEFAULT 'safe',  -- safe, suspicious, high_risk, critical
    explanation TEXT,  -- JSON array of reasons
    recommended_action VARCHAR(20) DEFAULT 'allow',  -- allow, spam, quarantine, block
    scored_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- ATTACHMENTS
-- ============================================
CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    filename VARCHAR(255),
    content_type VARCHAR(100),
    file_size INTEGER,
    file_hash VARCHAR(64),
    is_suspicious BOOLEAN DEFAULT FALSE,
    extracted_text TEXT,
    metadata TEXT,  -- JSON
    embedded_urls TEXT,  -- JSON array
    threat_detected BOOLEAN DEFAULT FALSE,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- URLS
-- ============================================
CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    domain VARCHAR(255),
    is_shortened BOOLEAN DEFAULT FALSE,
    final_url TEXT,
    domain_age_days INTEGER,
    is_malicious BOOLEAN DEFAULT FALSE,
    reputation_score REAL DEFAULT 50.0,
    tld VARCHAR(20),
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- ALERTS
-- ============================================
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER REFERENCES emails(id) ON DELETE SET NULL,
    alert_type VARCHAR(50) NOT NULL,  -- critical_threat, bomb_threat, mass_campaign, suspicious
    severity VARCHAR(20) NOT NULL DEFAULT 'info',  -- info, warning, high, critical
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    details TEXT,  -- JSON
    is_acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by INTEGER REFERENCES users(id),
    acknowledged_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- CASES
-- ============================================
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_number VARCHAR(50) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(20) DEFAULT 'open',  -- open, in_progress, closed, escalated
    priority VARCHAR(20) DEFAULT 'medium',  -- low, medium, high, critical
    assigned_to INTEGER REFERENCES users(id),
    created_by INTEGER REFERENCES users(id),
    email_ids TEXT,  -- JSON array of related email IDs
    evidence TEXT,  -- JSON array
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP
);

-- ============================================
-- AUDIT LOGS
-- ============================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id INTEGER,
    details TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- EMAIL ACTIONS
-- ============================================
CREATE TABLE IF NOT EXISTS email_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    action VARCHAR(20) NOT NULL,  -- allow, spam, quarantine, block, delete
    reason TEXT,
    triggered_by VARCHAR(20) DEFAULT 'system',  -- system, manual
    performed_by INTEGER REFERENCES users(id),
    performed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- ANALYST FEEDBACK
-- ============================================
CREATE TABLE IF NOT EXISTS analyst_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    analyst_id INTEGER NOT NULL REFERENCES users(id),
    original_classification VARCHAR(50),
    corrected_classification VARCHAR(50),  -- threat, safe, false_positive
    notes TEXT,
    used_for_training BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- INDEXES
-- ============================================
CREATE INDEX IF NOT EXISTS idx_emails_sender ON emails(sender_email);
CREATE INDEX IF NOT EXISTS idx_emails_status ON emails(status);
CREATE INDEX IF NOT EXISTS idx_emails_upload_date ON emails(upload_date);
CREATE INDEX IF NOT EXISTS idx_threat_analyses_email ON threat_analyses(email_id);
CREATE INDEX IF NOT EXISTS idx_threat_scores_email ON threat_scores(email_id);
CREATE INDEX IF NOT EXISTS idx_threat_scores_category ON threat_scores(category);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
