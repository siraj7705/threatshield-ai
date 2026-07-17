# ThreatShield AI

AI-powered email threat detection and analysis platform. Scans emails for threats — bomb threats, violence, terror, extortion, harassment, phishing, malicious links — and automatically quarantines dangerous emails, alerts the admin, and provides a full forensic breakdown.

---

## Table of Contents

1. [What It Does](#what-it-does)
2. [How It Works](#how-it-works)
3. [Tech Stack](#tech-stack)
4. [Project Structure](#project-structure)
5. [Features](#features)
6. [Setting Up on a New PC](#setting-up-on-a-new-pc)
7. [Environment Variables](#environment-variables)
8. [Gmail Integration Setup](#gmail-integration-setup)
9. [Running the Project](#running-the-project)
10. [API Reference](#api-reference)

---

## What It Does

ThreatShield AI monitors your Gmail inbox (or accepts manually uploaded `.eml` files) and runs every email through a multi-layer analysis pipeline:

- **NLP threat detection** — detects bomb threats, violence, terror, extortion, harassment, school threats using phrase patterns and keyword density
- **Email header forensics** — checks SPF/DKIM/DMARC, detects spoofing and routing anomalies
- **URL analysis** — extracts all links, checks them against Google Safe Browsing API, flags suspicious domains and typosquatting
- **Domain reputation** — detects lookalike/typosquat sender domains (e.g. `paypa1.com`, `amazon-support.net`)
- **Composite risk scoring** — produces a 0–100 threat score with weighted signals
- **Auto-quarantine** — emails scoring ≥ 40 are moved to a Gmail quarantine label and the admin is notified by email
- **Trusted senders** — per-user whitelist; trusted senders are never quarantined (phishing URLs still alert)
- **Case management** — analysts can bundle related emails into investigation cases
- **PDF reports** — generate forensic PDF reports per email

---

## How It Works

### Analysis Pipeline

Every email (uploaded file or live Gmail) goes through these stages in order:

```
Email arrives
    │
    ▼
1. PARSE          Extract subject, body, headers, sender, attachments, URLs
    │
    ▼
2. NLP ENGINE     Keyword lexicons + phrase regex patterns
                  • Requires 3+ keywords OR a direct threat phrase to flag
                  • Single words like "gun", "kill", "bomb" alone = ignored
                  • Unambiguous words like "ransom", "detonate" = flag at 1
    │
    ▼
3. HEADER CHECK   SPF / DKIM / DMARC validation
                  Spoofing detection, IP origin
    │
    ▼
4. URL ANALYSIS   Extract all links from body + HTML
                  Google Safe Browsing API check
                  Heuristic checks: IP URLs, suspicious TLDs, typosquatting
    │
    ▼
5. DOMAIN CHECK   Sender domain reputation
                  Lookalike detection (paypal-secure.com)
                  Typosquat detection (paypa1.com)
                  Legitimate sending domains whitelisted (facebookmail.com etc.)
    │
    ▼
6. THREAT SCORE   Weighted composite 0–100:
                  NLP 40% + Keywords 15% + Sender 15% + Headers 15%
                  + Urgency 10% + Attachments 5%
    │
    ▼
7. TRUSTED CHECK  Is sender in user's trusted list?
                  YES → allow, no quarantine
                      → phishing URLs still alert
                      → strong threat phrase → notice only
                  NO  → proceed to action
    │
    ▼
8. ACTION         0–30  → Allow
                  31–60 → Spam
                  61–80 → Quarantine
                  81–100→ Block
    │
    ▼
9. ALERT          Score ≥ 40 → Save alert to DB
                  Gmail scan → Quarantine label + admin email notification
```

### Threat Score Categories

| Score | Category | Action |
|-------|----------|--------|
| 0 – 30 | Safe | Allow |
| 31 – 60 | Suspicious | Spam |
| 61 – 80 | High Risk | Quarantine |
| 81 – 100 | Critical | Block |

### False Positive Prevention

- **Word boundary matching** — `"deadline"` does not match `"dead"`, `"skill"` does not match `"kill"`
- **Minimum signal threshold** — 1 keyword = 0.15 confidence (not a threat), need 3+ or a direct phrase
- **Legitimate sender whitelist** — `facebookmail.com`, `students.udemy.com`, `amazonses.com` etc. are never flagged
- **Lookalike requires corroboration** — domain lookalike alone is not enough; needs NLP signal or phishing body language too
- **Trusted senders** — per-user whitelist bypasses all threat actions

---

## Tech Stack

### Backend
| Component | Technology |
|-----------|-----------|
| Framework | FastAPI 0.115 (async) |
| Database | SQLite (dev) / PostgreSQL (prod) via SQLAlchemy 2.0 async |
| Auth | JWT (python-jose) + bcrypt |
| Email parsing | mail-parser |
| NLP | Custom rule-based engine (no ML model required) |
| PDF reports | ReportLab |
| Gmail | Google Gmail API + Cloud Pub/Sub |
| URL checking | Google Safe Browsing API v4 |
| Server | Uvicorn with hot-reload |

### Frontend
| Component | Technology |
|-----------|-----------|
| Framework | React 18 + TypeScript |
| Build tool | Vite |
| Styling | Tailwind CSS |
| Routing | React Router v6 |
| HTTP client | Axios with JWT interceptors |
| Charts | Recharts |
| File upload | react-dropzone |

---

## Project Structure

```
threatshield-ai/
├── backend/
│   ├── app/
│   │   ├── api/                  # Route handlers
│   │   │   ├── auth.py           # Login, register, refresh
│   │   │   ├── emails.py         # Upload & analyze emails
│   │   │   ├── alerts.py         # Alert management
│   │   │   ├── cases.py          # Investigation cases
│   │   │   ├── dashboard.py      # Stats & charts
│   │   │   ├── gmail.py          # Gmail watch + webhook
│   │   │   ├── reports.py        # PDF report generation
│   │   │   ├── threats.py        # Threat query endpoints
│   │   │   └── trusted_senders.py# Trusted sender whitelist
│   │   ├── core/
│   │   │   ├── config.py         # Settings from .env
│   │   │   ├── database.py       # SQLAlchemy engine + session
│   │   │   ├── security.py       # JWT + password hashing
│   │   │   └── gmail_auth.py     # Gmail OAuth2 flow
│   │   ├── models/               # SQLAlchemy ORM models
│   │   │   ├── user.py
│   │   │   ├── email.py
│   │   │   ├── threat.py         # ThreatAnalysis + ThreatScore
│   │   │   ├── header.py         # HeaderAnalysis
│   │   │   ├── url_analysis.py   # URLAnalysis (links + Safe Browsing)
│   │   │   ├── alert.py
│   │   │   ├── case.py
│   │   │   ├── audit.py
│   │   │   └── trusted_sender.py
│   │   ├── services/             # Business logic
│   │   │   ├── nlp_engine.py     # Threat language detection
│   │   │   ├── threat_scorer.py  # Composite risk scoring
│   │   │   ├── header_analyzer.py# SPF/DKIM/DMARC/spoofing
│   │   │   ├── url_analyzer.py   # Link extraction + Safe Browsing
│   │   │   ├── domain_checker.py # Lookalike/typosquat detection
│   │   │   ├── email_parser.py   # .eml / raw text parsing
│   │   │   ├── gmail_scanner.py  # Full Gmail scan pipeline
│   │   │   ├── gmail_watcher.py  # Pub/Sub watch management
│   │   │   ├── alert_engine.py   # Alert generation logic
│   │   │   └── report_generator.py# PDF forensic reports
│   │   ├── schemas/              # Pydantic request/response models
│   │   └── main.py               # FastAPI app entry point
│   ├── credentials.json          # Gmail OAuth credentials (keep secret)
│   ├── gmail_token.json          # Gmail access token (keep secret)
│   ├── requirements.txt
│   ├── .env                      # Environment variables (keep secret)
│   └── threatshield.db           # SQLite database (auto-created)
│
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── DashboardPage.tsx
│   │   │   ├── EmailsPage.tsx
│   │   │   ├── AlertsPage.tsx
│   │   │   ├── CasesPage.tsx
│   │   │   ├── GmailPage.tsx
│   │   │   ├── TrustedSendersPage.tsx
│   │   │   └── LoginPage.tsx
│   │   ├── components/           # Reusable UI components
│   │   ├── services/api.ts       # All API calls (axios)
│   │   ├── types/index.ts        # TypeScript interfaces
│   │   ├── store/auth.ts         # Auth state management
│   │   └── App.tsx               # Routes
│   ├── package.json
│   └── index.html
│
└── database/
    └── schema.sql                # Reference SQL schema
```

---

## Features

### Dashboard
- Total emails, threats, blocked, quarantined counts
- Threat trend chart (last 7/30 days)
- Severity distribution pie chart
- Top threat types breakdown
- Recent alerts feed

### Email Analysis
- Upload `.eml`, `.txt`, `.msg` files (up to 25 MB, batch supported)
- Full analysis: NLP + headers + URLs + domain + scoring
- Email detail modal with:
  - Threat score ring with per-signal breakdown
  - Detected keywords highlighted
  - Header forensics (SPF/DKIM/DMARC, origin IP/country)
  - Link inspector — every URL color-coded safe/suspicious/malicious
  - ⭐ Mark sender as trusted directly from the detail view
- PDF forensic report download

### Gmail Live Monitoring
- OAuth2 connection to Gmail inbox
- Google Cloud Pub/Sub push webhook — emails scanned in real time as they arrive
- Batch scan of past inbox emails (catches emails missed while monitoring was off)
- Auto-applies Gmail labels: `ThreatShield-Quarantine` / `ThreatShield-Safe`
- Admin email notification on threat detection (rich HTML email with full details)

### Alerts
- Severity levels: critical / high / warning / info
- Acknowledge alerts
- Unacknowledged count badge in nav

### Cases
- Bundle related emails into investigation cases
- Status tracking: open → in-progress → closed
- Priority levels: low / medium / high / critical
- Add investigation notes

### Trusted Senders
- Per-user whitelist (each user has their own list)
- Add exact email (`boss@company.com`) or whole domain (`@company.com`)
- Trusted emails are never quarantined or blocked
- Phishing URLs from trusted senders still generate a high alert
- Strong threat phrases from trusted senders generate a low-priority notice only
- Quick-add ⭐ from email list row or email detail modal

---

## Setting Up on a New PC

### Prerequisites

Install these first:

| Tool | Version | Download |
|------|---------|----------|
| Python | 3.10 or higher | https://python.org/downloads |
| Node.js | 18 or higher | https://nodejs.org |
| Git | any | https://git-scm.com |
| ngrok | any | https://ngrok.com/download (only needed for Gmail live monitoring) |

Verify installations:
```bash
python --version    # should be 3.10+
node --version      # should be 18+
git --version
```

---

### Step 1 — Copy the project files

Either copy the folder to the new PC, or push to Git and clone:

```bash
git clone <your-repo-url>
cd threatshield-ai
```

---

### Step 2 — Backend setup

```bash
cd backend
```

**Create virtual environment:**
```bash
python -m venv venv
```

**Activate it:**
- Windows: `venv\Scripts\activate`
- Mac/Linux: `source venv/bin/activate`

**Install dependencies:**
```bash
pip install fastapi==0.115.6 uvicorn[standard]==0.34.0 python-multipart==0.0.20 \
  sqlalchemy[asyncio]==2.0.36 aiosqlite==0.20.0 python-jose[cryptography]==3.3.0 \
  passlib[bcrypt]==1.7.4 bcrypt==4.0.1 mail-parser==3.15.0 python-dateutil==2.9.0 \
  reportlab==4.2.5 pydantic==2.10.4 pydantic-settings==2.7.1 python-dotenv==1.0.1 \
  aiofiles==24.1.0 httpx==0.28.1 jinja2==3.1.5 google-auth==2.37.0 \
  google-auth-oauthlib==1.2.1 google-auth-httplib2==0.2.0 \
  google-api-python-client==2.154.0 numpy==1.26.4 scikit-learn==1.6.1
```

> **Note:** `bcrypt==4.0.1` is intentional — version 4.2+ has a compatibility issue with passlib.

**Create the `.env` file** (copy from the template below and fill in your values):
```bash
# Windows
copy .env.example .env

# Mac/Linux
cp .env.example .env
```

Then edit `.env` — see [Environment Variables](#environment-variables) section below.

**Copy secret files** (these are machine-specific and should NOT be in git):
- `credentials.json` — Gmail OAuth credentials from Google Cloud Console
- `gmail_token.json` — generated after first Gmail login (copy from old PC or re-authenticate)

---

### Step 3 — Frontend setup

Open a new terminal:

```bash
cd frontend
npm install
```

---

### Step 4 — Start the backend

```bash
cd backend
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

You should see:
```
INFO: Uvicorn running on http://0.0.0.0:8000
INFO: Database initialized.
INFO: Application startup complete.
```

The database (`threatshield.db`) is created automatically on first run.

---

### Step 5 — Start the frontend

```bash
cd frontend
npm run dev
```

You should see:
```
VITE v6.x  ready in 2000ms
➜  Local:   http://localhost:5173/
```

---

### Step 6 — Create your account

Open `http://localhost:5173` in your browser.

You'll land on the login page. Register a new account first:
- Go to `http://localhost:8000/docs` (Swagger UI)
- Find `POST /api/auth/register`
- Fill in username, email, password, role (`admin`)
- Or register through the login page if the UI has a register link

Then log in with your credentials.

---

### Step 7 — Start ngrok (for Gmail live monitoring only)

If you want real-time Gmail scanning:

```bash
ngrok http 8000
```

Copy the `https://xxxx.ngrok-free.app` URL and put it in your `.env` as `APP_BASE_URL`.

Then in the app, go to **Gmail Watch** page and click **Start**.

---

## Environment Variables

Create `backend/.env` with these values:

```env
# App
APP_NAME=ThreatShield AI
APP_ENV=development
DEBUG=true
SECRET_KEY=change-this-to-a-long-random-string
API_HOST=0.0.0.0
API_PORT=8000

# Database (SQLite for local dev, PostgreSQL for production)
DATABASE_URL=sqlite+aiosqlite:///./threatshield.db

# JWT (change these to random strings in production)
JWT_SECRET_KEY=change-this-jwt-secret
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# CORS — frontend URL
CORS_ORIGINS=http://localhost:5173,http://localhost:3000

# Email file settings
MAX_EMAIL_SIZE_MB=25
ALLOWED_EXTENSIONS=.eml,.msg,.txt

# Logging
LOG_LEVEL=INFO
LOG_FILE=./logs/threatshield.log

# Gmail Integration (needed only for live Gmail monitoring)
GMAIL_CREDENTIALS_FILE=credentials.json
GMAIL_TOKEN_FILE=gmail_token.json
GMAIL_PUBSUB_TOPIC=projects/YOUR_PROJECT_ID/topics/threatshield-gmail
GMAIL_ADMIN_EMAIL=your-email@gmail.com
GMAIL_WATCHER_EMAIL=your-email@gmail.com
APP_BASE_URL=https://your-ngrok-url.ngrok-free.app

# Google Safe Browsing API (optional — for URL malware checking)
GOOGLE_SAFE_BROWSING_API_KEY=your-key-here
```

---

## Gmail Integration Setup

This is only needed if you want live Gmail inbox monitoring. The manual email upload feature works without any of this.

### 1. Create a Google Cloud Project

1. Go to https://console.cloud.google.com
2. Create a new project, name it `ThreatShield`
3. Enable these APIs in **APIs & Services → Library**:
   - Gmail API
   - Cloud Pub/Sub API

### 2. Create OAuth Credentials

1. Go to **APIs & Services → Credentials**
2. Click **Create Credentials → OAuth client ID**
3. Application type: **Desktop App**
4. Download the JSON file
5. Rename it to `credentials.json`
6. Place it in the `backend/` folder

### 3. Create Pub/Sub Topic

1. Go to https://console.cloud.google.com/cloudpubsub/topic/list
2. Create a topic named `threatshield-gmail`
3. Add `gmail-api-push@system.gserviceaccount.com` as a **Publisher** on that topic

### 4. Create Pub/Sub Subscription

1. Create a **Push** subscription on that topic
2. Set the endpoint URL to: `https://your-ngrok-url.ngrok-free.app/api/gmail/webhook`
3. Update `APP_BASE_URL` in `.env` with your ngrok URL

### 5. Authenticate Gmail

Run this once to open the browser OAuth consent screen:

```bash
cd backend
venv\Scripts\activate
python -c "from app.core.gmail_auth import get_credentials; get_credentials()"
```

A browser window opens. Log in with the Gmail account you want to monitor. This creates `gmail_token.json` in `backend/`.

### 6. Start Watching

In the app, go to **Gmail Watch** page and click **▶ Start**. ThreatShield will now auto-scan every new inbox email.

> **Note:** The Gmail watch subscription expires every 7 days. You need to click Start again to renew it (or automate renewal with a cron job).

---

## Running the Project

### Normal startup (both terminals needed)

**Terminal 1 — Backend:**
```bash
cd backend
venv\Scripts\activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 — Frontend:**
```bash
cd frontend
npm run dev
```

**Terminal 3 — ngrok (only for Gmail live monitoring):**
```bash
ngrok http 8000
```

### URLs

| Service | URL |
|---------|-----|
| Frontend app | http://localhost:5173 |
| Backend API | http://localhost:8000 |
| Swagger API docs | http://localhost:8000/docs |
| ngrok dashboard | http://localhost:4040 |

---

## API Reference

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new account |
| POST | `/api/auth/login` | Login, returns JWT tokens |
| POST | `/api/auth/refresh` | Refresh access token |
| GET | `/api/auth/me` | Get current user info |

### Emails
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/emails/upload` | Upload and analyze a single .eml/.txt/.msg |
| POST | `/api/emails/upload/batch` | Upload multiple files |
| GET | `/api/emails` | List emails (paginated) |
| GET | `/api/emails/{id}` | Full email detail with all analysis |
| DELETE | `/api/emails/{id}` | Delete email record |

### Alerts
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts` | List alerts |
| PUT | `/api/alerts/{id}/acknowledge` | Acknowledge an alert |
| GET | `/api/alerts/unacknowledged/count` | Count of unread alerts |

### Cases
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/cases` | List cases |
| POST | `/api/cases` | Create new case |
| GET | `/api/cases/{id}` | Case detail |
| PUT | `/api/cases/{id}/status` | Update case status |
| POST | `/api/cases/{id}/notes` | Add investigation note |

### Gmail
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/gmail/watch/start` | Start Gmail push monitoring |
| POST | `/api/gmail/watch/stop` | Stop Gmail push monitoring |
| POST | `/api/gmail/webhook` | Pub/Sub push webhook (called by Google) |
| POST | `/api/gmail/scan/{gmail_id}` | Manually scan one Gmail message |
| POST | `/api/gmail/scan/batch` | Scan recent inbox emails |
| GET | `/api/gmail/status` | Check integration status |

### Trusted Senders
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/trusted-senders` | List your trusted senders |
| POST | `/api/trusted-senders` | Add email or @domain |
| DELETE | `/api/trusted-senders/{id}` | Remove a trusted sender |
| GET | `/api/trusted-senders/check?email=` | Check if an email is trusted |

### Reports
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/reports/email/{id}/pdf` | Download PDF forensic report |
| GET | `/api/reports/summary` | Summary statistics |

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard/stats` | Stats, trends, charts data |

---

## Common Issues

**`bcrypt` error on login/register:**
```bash
pip install bcrypt==4.0.1
```

**Port 8000 already in use:**
```bash
# Windows
netstat -ano | findstr :8000
taskkill /PID <pid> /F
```

**ngrok tunnel already online error:**
```bash
# Kill existing ngrok and restart
taskkill /F /IM ngrok.exe
ngrok http 8000
```

**Gmail watch expired (stops scanning after 7 days):**
- Go to Gmail Watch page in the app
- Click ▶ Start to renew

**Database needs reset:**
```bash
cd backend
del threatshield.db    # Windows
# rm threatshield.db   # Mac/Linux
# Restart backend — tables recreated automatically
```

---

## Security Notes

- `credentials.json` and `gmail_token.json` contain sensitive OAuth secrets — never commit them to a public repository
- Change `SECRET_KEY` and `JWT_SECRET_KEY` in `.env` before any production use
- The SQLite database contains all email content and analysis data — keep it secure
- The Google Safe Browsing API key in `.env` should be restricted to your IP in Google Cloud Console
