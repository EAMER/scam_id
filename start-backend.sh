#!/bin/bash

# Scam Detector Backend Starter (Linux/Mac)

echo ""
echo "====================================="
echo "  Scam Detector Backend Starter"
echo "====================================="
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Error: Node.js is not installed"
    echo "Please download and install Node.js from https://nodejs.org/"
    exit 1
fi

echo "✓ Node.js detected: $(node --version)"
echo ""

# Check if backend directory exists
if [ ! -d "backend" ]; then
    echo "❌ Error: backend directory not found"
    echo "Please run this script from the Scam_detector root directory"
    exit 1
fi

cd backend

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
    if [ $? -ne 0 ]; then
        echo "❌ Error installing dependencies"
        exit 1
    fi
    echo "✓ Dependencies installed"
    echo ""
fi

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "📝 Creating .env file from template..."
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "✓ .env file created"
    else
        echo "⚠️  .env.example not found"
    fi
    echo ""
fi

# Start the server
echo "🚀 Starting Scam Detector Backend..."
echo ""
echo "📍 API will be available at: http://localhost:3000"
echo "📍 Scan endpoint: http://localhost:3000/scan"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

npm run dev
