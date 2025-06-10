#!/usr/bin/env python3

from flask import Flask, render_template, jsonify, request, send_from_directory
import pandas as pd
import json
import os
from datetime import datetime
import threading
import time


app = Flask(__name__)

class DashboardManager:
    def __init__(self):
        self.stats = {
            'total_flows': 0,
            'malicious_flows': 0,
            'benign_flows': 0,
            'detection_rate': 0.0,
            'false_positive_rate': 0.0,
            'current_attacks': []
        }
        self.update_stats()
    
    def update_stats(self):
        """Update dashboard statistics"""
        dataset_path = '/app/data/ddos_dataset.csv'
        
        if os.path.exists(dataset_path):
            try:
                df = pd.read_csv(dataset_path)
                
                self.stats['total_flows'] = len(df)
                self.stats['malicious_flows'] = len(df[df['label'] == 1])
                self.stats['benign_flows'] = len(df[df['label'] == 0])
                
                if self.stats['total_flows'] > 0:
                    self.stats['detection_rate'] = (
                        self.stats['malicious_flows'] / self.stats['total_flows']
                    ) * 100
                
            except Exception as e:
                print(f"Error updating stats: {e}")
    
    def get_recent_attacks(self):
        """Get recent attack information"""
        dataset_path = '/app/data/ddos_dataset.csv'
        
        if os.path.exists(dataset_path):
            try:
                df = pd.read_csv(dataset_path)
                recent_attacks = df[df['label'] == 1].tail(10)
                
                attacks = []
                for _, row in recent_attacks.iterrows():
                    attacks.append({
                        'timestamp': datetime.fromtimestamp(row['dt']).strftime('%Y-%m-%d %H:%M:%S'),
                        'src_ip': row['src_ip'],
                        'dst_ip': row['dst_ip'],
                        'packet_rate': row['packet_rate'],
                        'severity': 'High' if row['packet_rate'] > 100 else 'Medium'
                    })
                
                return attacks
            except Exception as e:
                print(f"Error getting recent attacks: {e}")
        
        return []

dashboard_manager = DashboardManager()

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """API endpoint for statistics"""
    dashboard_manager.update_stats()
    return jsonify(dashboard_manager.stats)

@app.route('/api/attacks')
def get_attacks():
    """API endpoint for recent attacks"""
    attacks = dashboard_manager.get_recent_attacks()
    return jsonify(attacks)

@app.route('/api/traffic_chart')
def traffic_chart():
    """API endpoint for traffic chart data"""
    dataset_path = '/app/data/ddos_dataset.csv'
    
    if os.path.exists(dataset_path):
        try:
            df = pd.read_csv(dataset_path)
            
            # Group by time intervals
            df['timestamp'] = pd.to_datetime(df['dt'], unit='s')
            df_resampled = df.set_index('timestamp').resample('1Min').agg({
                'label': ['count', 'sum']
            })
            
            chart_data = {
                'timestamps': df_resampled.index.strftime('%H:%M').tolist(),
                'benign': (df_resampled[('label', 'count')] - df_resampled[('label', 'sum')]).tolist(),
                'malicious': df_resampled[('label', 'sum')].tolist()
            }
            
            return jsonify(chart_data)
        except Exception as e:
            print(f"Error generating chart data: {e}")
    
    return jsonify({'timestamps': [], 'benign': [], 'malicious': []})

@app.route('/api/training_results/<path:filename>')
def serve_training_image(filename):
    """API endpoint to serve training result images."""
    # Pastikan path absolut ke direktori models
    return send_from_directory('/app/models', filename)

if __name__ == '__main__':
    # Start background stats updater
    def update_loop():
        while True:
            time.sleep(30)  # Update every 30 seconds
            dashboard_manager.update_stats()
    
    updater_thread = threading.Thread(target=update_loop)
    updater_thread.daemon = True
    updater_thread.start()
    
    app.run(host='0.0.0.0', port=5000, debug=True)
