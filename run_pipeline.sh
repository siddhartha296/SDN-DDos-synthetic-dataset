#!/bin/bash

echo "=========================================="
echo "SDN-DDoS Dataset Generation Pipeline"
echo "=========================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

# Create output directory
mkdir -p output
cd output

echo -e "\n${GREEN}Step 1: Starting Ryu Controller${NC}"
ryu-manager ../ryu_controller.py --verbose > ryu.log 2>&1 &
RYU_PID=$!
echo "Ryu PID: $RYU_PID"
sleep 5

# Check if Ryu started successfully
if ! ps -p $RYU_PID > /dev/null; then
    echo -e "${RED}Failed to start Ryu controller${NC}"
    exit 1
fi

echo -e "${GREEN}Step 2: Running Mininet Topologies${NC}"
python3 ../mininet_topology.py

echo -e "\n${GREEN}Step 3: Stopping Ryu Controller${NC}"
kill $RYU_PID
sleep 2

echo -e "\n${GREEN}Step 4: Building Dataset${NC}"
cd ..
python3 dataset_builder.py

echo -e "\n${GREEN}=========================================="
echo -e "Pipeline Complete!"
echo -e "==========================================${NC}"
echo -e "\nGenerated files in output/ directory:"
ls -lh output/*.csv

