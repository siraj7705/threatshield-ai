"""
LOCATION: threatshield-ai/backend/app/core/config.py

ThreatShield AI - Application Configuration
"""
from pydantic_settings import BaseSettings
from typing import List
import os


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "ThreatShield AI"
    APP_ENV: str = "development"
    DEBUG: bool = True
    SECRET_KEY: str = "change-this-to-a-secure-random-string-in-production"
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://threatshield:threatshield@postgres:5432/threatshield"

    # JWT
    JWT_SECRET_KEY: str = "your-jwt-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    # NLP
    NLP_MODEL_PATH: str = "./ml_models"
    SPACY_MODEL: str = "en_core_web_sm"

    # Email Processing
    MAX_EMAIL_SIZE_MB: int = 25
    ALLOWED_EXTENSIONS: str = ".eml,.msg,.txt"

    # Gmail Integration — LEGACY single-mailbox desktop OAuth flow
    GMAIL_CREDENTIALS_FILE: str = "credentials.json"
    GMAIL_TOKEN_FILE: str = "gmail_token.json"
    GMAIL_PUBSUB_TOPIC: str = ""
    GMAIL_ADMIN_EMAIL: str = ""
    GMAIL_WATCHER_EMAIL: str = ""
    APP_BASE_URL: str = "http://localhost:8000"

    # Gmail Integration — per-user OAuth (Web application client)
    GMAIL_OAUTH_CLIENT_ID: str = ""
    GMAIL_OAUTH_CLIENT_SECRET: str = ""
    GMAIL_OAUTH_REDIRECT_URI: str = "http://localhost:8000/api/gmail/oauth/callback"
    FRONTEND_BASE_URL: str = "http://localhost:5173"

    # URL Analysis
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""

    # IP Reputation / VPN-Tor-Proxy Detection
    IP_REPUTATION_PROVIDER: str = "ip-api"
    IP_REPUTATION_API_KEY: str = ""

    # Domain Age / WHOIS Lookup
    DOMAIN_AGE_PROVIDER: str = "rdap"
    DOMAIN_AGE_NEW_DOMAIN_DAYS: int = 30

    # ClamAV (attachment malware scanning)
    CLAMAV_HOST: str = "clamav"
    CLAMAV_PORT: int = 3310

    # Elasticsearch
    ELASTICSEARCH_URL: str = "http://elasticsearch:9200"
    ELASTICSEARCH_ENABLED: bool = True

    # ── Twilio — Real-Time SMS & Voice Alerting ───────────────────────────────
    # Get credentials from https://www.twilio.com (free trial available)
    #
    # Add these to your .env file:
    #   TWILIO_ENABLED=true
    #   TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    #   TWILIO_AUTH_TOKEN=your_auth_token_here
    #   TWILIO_FROM_NUMBER=+1xxxxxxxxxx        (your Twilio number)
    #   TWILIO_TO_NUMBERS=+1xxxxxxxxxx,+1xxxxxxxxxx  (recipients, comma-separated)
    #   TWILIO_SMS_SEVERITY_THRESHOLD=high     (warning | high | critical)
    #   TWILIO_VOICE_ENABLED=true              (voice calls for critical alerts only)
    #   TWILIO_TWIML_URL=                      (optional: hosted TwiML URL; leave blank to use built-in message)
    #
    # Install the Twilio SDK:  pip install twilio
    TWILIO_ENABLED: bool = False
    TWILIO_ACCOUNT_SID: str = ""
    TWILIO_AUTH_TOKEN: str = ""
    TWILIO_FROM_NUMBER: str = ""
    TWILIO_TO_NUMBERS: str = ""          # comma-separated E.164 numbers
    TWILIO_SMS_SEVERITY_THRESHOLD: str = "high"   # warning | high | critical
    TWILIO_VOICE_ENABLED: bool = False   # voice calls for critical alerts only
    TWILIO_TWIML_URL: str = ""           # optional hosted TwiML URL

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "./logs/threatshield.log"

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

    @property
    def allowed_extensions_list(self) -> List[str]:
        return [ext.strip() for ext in self.ALLOWED_EXTENSIONS.split(",")]

    @property
    def twilio_to_numbers_list(self) -> List[str]:
        return [n.strip() for n in self.TWILIO_TO_NUMBERS.split(",") if n.strip()]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"


settings = Settings()