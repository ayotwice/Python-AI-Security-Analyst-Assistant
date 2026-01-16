#!/bin/bash
# Start script for Bespin Security Suite
# This starts both the AgentOS backend and AgentUI frontend

set -e

# Load nvm
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

# Get VM public IP
VM_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')

echo "============================================"
echo "🛡️  AI Security Analyst - Startup"
echo "============================================"
echo ""
echo "VM Public IP: $VM_IP"
echo ""

# Check for API key
if [ -z "$GEMINI_API_KEY" ] && [ -z "$GOOGLE_API_KEY" ] && [ -z "$OPENROUTER_API_KEY" ]; then
    echo "⚠️  Warning: No API key found!"
    echo "   Set GEMINI_API_KEY or OPENROUTER_API_KEY before running."
    echo ""
fi

# Activate Python venv
source .venv/bin/activate

echo "Starting services..."
echo ""

# Start AgentOS backend in background
echo "📡 Starting AgentOS backend on http://0.0.0.0:7777"
python agentos.py &
BACKEND_PID=$!
sleep 3

# Start AgentUI frontend in background
echo "🖥️  Starting AgentUI frontend on http://0.0.0.0:3000"
cd agent-ui
HOST=0.0.0.0 npm run dev &
FRONTEND_PID=$!
cd ..

sleep 5

echo ""
echo "============================================"
echo "✅ Services Started!"
echo "============================================"
echo ""
echo "🌐 Access from your local machine:"
echo ""
echo "   AgentUI:  http://$VM_IP:3000"
echo "   Backend:  http://$VM_IP:7777"
echo ""
echo "📋 How to connect:"
echo "   1. Open http://$VM_IP:3000 in your browser"
echo "   2. Click 'Add new OS' → 'Local'"
echo "   3. Enter endpoint: http://$VM_IP:7777"
echo "   4. Start chatting with Security Analyst!"
echo ""
echo "🛑 To stop services: kill $BACKEND_PID $FRONTEND_PID"
echo ""
echo "============================================"

# Wait for processes
wait
