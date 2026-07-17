#!/bin/sh
# ThreatShield AI - backend container entrypoint
# Waits for Postgres to accept connections, runs Alembic migrations,
# then starts the API server.
set -e

echo "[entrypoint] Waiting for Postgres at ${POSTGRES_HOST:-postgres}:${POSTGRES_PORT:-5432}..."
ATTEMPTS=0
MAX_ATTEMPTS=60
until python -c "
import socket, sys, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1)
try:
    s.connect((os.environ.get('POSTGRES_HOST', 'postgres'), int(os.environ.get('POSTGRES_PORT', 5432))))
    s.close()
except Exception:
    sys.exit(1)
" 2>/dev/null; do
  ATTEMPTS=$((ATTEMPTS + 1))
  if [ "$ATTEMPTS" -ge "$MAX_ATTEMPTS" ]; then
    echo "[entrypoint] Postgres did not become available in time, exiting."
    exit 1
  fi
  sleep 1
done
echo "[entrypoint] Postgres is up."

echo "[entrypoint] Running database migrations..."
alembic upgrade head

echo "[entrypoint] Starting application..."
exec "$@"
