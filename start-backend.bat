@echo off
echo.
echo =====================================
echo   Scam Detector Backend Starter
echo =====================================
echo.

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Error: Node.js is not installed
    echo Please download and install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

echo ✓ Node.js detected
echo.

REM Navigate to backend directory
if not exist "backend" (
    echo ❌ Error: backend directory not found
    echo Please run this script from the Scam_detector root directory
    pause
    exit /b 1
)

cd backend

REM Check if node_modules exists
if not exist "node_modules" (
    echo 📦 Installing dependencies...
    call npm install
    if errorlevel 1 (
        echo ❌ Error installing dependencies
        pause
        exit /b 1
    )
    echo ✓ Dependencies installed
    echo.
)

REM Check if .env exists
if not exist ".env" (
    echo 📝 Creating .env file from template...
    if exist ".env.example" (
        copy .env.example .env
        echo ✓ .env file created
    ) else (
        echo ⚠️  .env.example not found
    )
    echo.
)

REM Start the server
echo 🚀 Starting Scam Detector Backend...
echo.
echo 📍 API will be available at: http://localhost:3000
echo 📍 Scan endpoint: http://localhost:3000/scan
echo.
echo Press Ctrl+C to stop the server
echo.

call npm run dev

pause
