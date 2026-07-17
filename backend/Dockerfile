# =============================================
# LOCATION: threatshield-ai/backend/Dockerfile
# =============================================

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
# - build-essential/curl: existing
# - libmagic1: file type sniffing used by attachment scanner
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Download spaCy model
RUN python -m spacy download en_core_web_sm

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs ml_models

# Entrypoint waits for Postgres + runs Alembic migrations before boot
RUN chmod +x docker-entrypoint.sh

# Expose port
EXPOSE 8000

ENTRYPOINT ["./docker-entrypoint.sh"]

# Start command
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]