#!/bin/bash
set -e

echo "🛡️  ThreatShield AI Setup"
echo "========================="

# Backend
echo ""
echo "📦 Setting up backend..."
cd backend

if [ ! -f .env ]; then
  cp ../.env.example .env
  echo "✅ Created .env from .env.example"
fi

python3 -m venv venv 2>/dev/null || python -m venv venv
source venv/bin/activate

pip install -r requirements.txt

echo "✅ Backend dependencies installed"
cd ..

# Frontend
echo ""
echo "🎨 Setting up frontend..."
cd frontend

if ! command -v node &>/dev/null; then
  echo "❌ Node.js not found. Install from https://nodejs.org"
  exit 1
fi

npm install
echo "✅ Frontend dependencies installed"
cd ..

echo ""
echo "✨ Setup complete!"
echo ""
echo "To start the app:"
echo "  Terminal 1 (backend):  cd backend && source venv/bin/activate && uvicorn app.main:app --reload"
echo "  Terminal 2 (frontend): cd frontend && npm run dev"
echo ""
echo "  Backend:  http://localhost:8000"
echo "  Frontend: http://localhost:5173"
echo "  API Docs: http://localhost:8000/docs"
