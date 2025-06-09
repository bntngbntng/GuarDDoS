#!/bin/bash

# Start OVS
service openvswitch-switch start
sleep 2

# Start Ryu controller in background
echo "Starting Ryu Controller..."
ryu-manager /app/controller/ddos_controller.py --verbose &
sleep 5

# Start the Dashboard in background
echo "Starting Web Dashboard..."
python3 /app/dashboard/dashboard.py &
sleep 5

# Start the main application (data collection & training)
echo "Starting Main Application..."
python3 /app/main.py

# Keep container running
echo "Main script finished, keeping container alive."
tail -f /dev/null
