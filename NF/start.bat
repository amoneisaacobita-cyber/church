@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js 22 or newer is required. Install Node.js, then run npm install in the backend folder.
  pause
  exit /b 1
)
cd /d "%~dp0backend"
if not exist "node_modules" npm install
if errorlevel 1 (
  echo Could not install backend dependencies.
  pause
  exit /b 1
)
node server.js
if errorlevel 1 (
  echo The Life Fountain Church server stopped.
  pause
)
