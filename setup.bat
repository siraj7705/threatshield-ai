@echo off
echo 🛡️  ThreatShield AI Setup
echo =========================

echo.
echo 📦 Setting up backend...
cd backend

IF NOT EXIST .env (
  copy ..\\.env.example .env
  echo ✅ Created .env from .env.example
)

python -m venv venv
call venv\Scripts\activate
pip install -r requirements.txt
echo ✅ Backend dependencies installed
cd ..

echo.
echo 🎨 Setting up frontend...
cd frontend
call npm install
echo ✅ Frontend dependencies installed
cd ..

echo.
echo ✨ Setup complete!
echo.
echo To start the app:
echo   Terminal 1 (backend):  cd backend ^&^& venv\Scripts\activate ^&^& uvicorn app.main:app --reload
echo   Terminal 2 (frontend): cd frontend ^&^& npm run dev
echo.
echo   Backend:  http://localhost:8000
echo   Frontend: http://localhost:5173
echo   API Docs: http://localhost:8000/docs
pause
