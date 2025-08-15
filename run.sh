#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Starting Procscope Web...${NC}"

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}⏹  Shutting down servers...${NC}"
    
    # Kill specific processes first
    if [ ! -z "$SERVER_PID" ]; then
        echo "Killing server (PID: $SERVER_PID)"
        kill -TERM $SERVER_PID 2>/dev/null
        sleep 2
        kill -KILL $SERVER_PID 2>/dev/null
    fi
    if [ ! -z "$CLIENT_PID" ]; then
        echo "Killing client (PID: $CLIENT_PID)"
        kill -TERM $CLIENT_PID 2>/dev/null
        sleep 2
        kill -KILL $CLIENT_PID 2>/dev/null
    fi
    
    # Kill any remaining child processes
    pkill -P $$ 2>/dev/null
    
    # Kill any remaining tsx/vite processes that might be hanging
    pkill -f "tsx server/index.ts" 2>/dev/null
    pkill -f "vite" 2>/dev/null
    
    echo -e "${GREEN}✅ Shutdown complete${NC}"
    exit 0
}

# Trap ctrl-c and call cleanup
trap cleanup INT TERM

# Check if dependencies are installed
if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}📦 Installing backend dependencies...${NC}"
    npm install
fi

if [ ! -d "client/node_modules" ]; then
    echo -e "${YELLOW}📦 Installing client dependencies...${NC}"
    cd client && npm install && cd ..
fi

# Start backend server
echo -e "${GREEN}🔧 Starting backend server on port 3000...${NC}"
npx tsx server/index.ts &
SERVER_PID=$!

# Wait for backend to be ready
echo -e "${YELLOW}⏳ Waiting for backend to start...${NC}"
while ! nc -z localhost 3000; do
    sleep 1
done
echo -e "${GREEN}✅ Backend is ready${NC}"

# Start client dev server
echo -e "${GREEN}🎨 Starting client on port 5173...${NC}"
cd client && npx vite &
CLIENT_PID=$!

# Wait for client to be ready
echo -e "${YELLOW}⏳ Waiting for client to start...${NC}"
sleep 3

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✨ Procscope is running!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "   🌐 Open in browser: ${GREEN}http://localhost:5173${NC}"
echo -e "   📡 API endpoint:    ${GREEN}http://localhost:3000/api${NC}"
echo -e "   🔌 WebSocket:       ${GREEN}ws://localhost:3000/ws${NC}"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop all servers${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Keep script running and wait for interrupt
wait