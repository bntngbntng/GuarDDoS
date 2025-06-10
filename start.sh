#!/bin/bash

# Pastikan direktori logs ada
mkdir -p /app/logs

# Hapus file log lama untuk sesi yang bersih
rm -f /app/logs/*.log

# Start OVS
echo "Starting Open vSwitch..."
service openvswitch-switch start
sleep 2

# Start Ryu controller, arahkan output ke file log
echo "Starting Ryu Controller... (logs in /app/logs/ryu.log)"
ryu-manager /app/controller/ddos_controller.py --verbose > /app/logs/ryu.log 2>&1 &
sleep 5

# Start the Dashboard, arahkan output ke file log
echo "Starting Web Dashboard... (logs in /app/logs/dashboard.log)"
python3 -u /app/dashboard/dashboard.py > /app/logs/dashboard.log 2>&1 &
sleep 5

# Start the main application
echo "Starting Main Application... (logs also in /app/logs/main.log)"
python3 -u /app/main.py | tee /app/logs/main.log

# Keep container running
echo "Main script finished, keeping container alive."
tail -f /dev/null
