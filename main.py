#!/usr/bin/env python3

import sys
import os
import time
import signal
import threading
import subprocess
import logging
from network.topology import DDoSTopology
from traffic.traffic_generator import TrafficGenerator
from ml.ml_models import DDoSMLModels, RealTimeDetector

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/system.log'),
        logging.StreamHandler()
    ]
)

class DDoSDetectionSystem:
    def __init__(self):
        self.topology = None
        self.traffic_generator = None
        self.net = None
        self.running = False
        self.logger = logging.getLogger(__name__)

    def setup_environment(self):
        """Setup the SDN environment"""
        self.logger.info("Setting up DDoS Detection Environment...")

        # Create data directories
        os.makedirs('/app/data', exist_ok=True)
        os.makedirs('/app/logs', exist_ok=True)
        os.makedirs('/app/models', exist_ok=True)

        # Setup network topology
        self.topology = DDoSTopology()
        self.net = self.topology.create_topology()

        if not self.topology.start_network():
            self.logger.error("Failed to start network!")
            return False

        self.logger.info("Starting web server on target host...")
        server = self.net.get('server')
        server.cmd('python3 -m http.server 8000 &')

        # Initialize traffic generator
        self.traffic_generator = TrafficGenerator(self.net)

        self.logger.info("Environment setup complete!")
        return True

    def collect_training_data(self, duration=300):
        """Starts traffic, waits for the collection period, and checks the result."""
        self.logger.info("Starting background traffic for data collection...")

        # 1. Mulai traffic di background (ini sekarang non-blocking dan kembali instan)
        self.traffic_generator.start_traffic_generation(duration)

        self.logger.info(f"Data collection is now running. Main process will wait for {duration} seconds...")

        # 2. Skrip utama (main.py) sekarang yang menunggu di sini.
        #    Selama ini, thread traffic dan controller berjalan normal.
        time.sleep(duration)

        self.logger.info("Data collection period has officially ended.")

        # 3. Beri sinyal ke thread traffic generator untuk berhenti membuat serangan baru.
        self.logger.info("Signaling traffic generator threads to stop.")
        self.traffic_generator.is_running = False

        # 4. Tunggu sebentar agar controller bisa memproses dan menyimpan batch data terakhir.
        #    Ini langkah PENTING.
        self.logger.info("Waiting 35 seconds for the controller to perform final data write...")
        time.sleep(35)

        # 5. Cek hasil akhir dataset.
        dataset_path = '/app/data/ddos_dataset.csv'
        self.logger.info(f"Checking for final dataset at {dataset_path}")

        if os.path.exists(dataset_path) and os.path.getsize(dataset_path) > 0:
            self.logger.info(f"Dataset created successfully: {dataset_path}")
            return dataset_path
        else:
            self.logger.error("Dataset file was not created or is empty! The pipeline will fail.")
            return None

    def validate_dataset(self, dataset_path):
        """Validate dataset quality before training"""
        try:
            import pandas as pd
            df = pd.read_csv(dataset_path)

            self.logger.info(f"Dataset validation:")
            self.logger.info(f"- Total samples: {len(df)}")
            self.logger.info(f"- Features: {len(df.columns)}")
            self.logger.info(f"- Missing values: {df.isnull().sum().sum()}")

            if 'label' in df.columns:
                benign_count = sum(df['label'] == 0)
                malicious_count = sum(df['label'] == 1)
                self.logger.info(f"- Benign samples: {benign_count}")
                self.logger.info(f"- Malicious samples: {malicious_count}")

                if benign_count == 0 or malicious_count == 0:
                    self.logger.warning("Dataset is unbalanced - missing one class!")
                    return False

            if len(df) < 100:
                self.logger.warning("Dataset too small for reliable training!")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Dataset validation failed: {e}")
            return False

    def train_models(self, dataset_path):
        """Train ML models on collected data"""
        if not dataset_path or not os.path.exists(dataset_path):
            self.logger.error("No dataset available for training!")
            return None

        # Validate dataset first
        if not self.validate_dataset(dataset_path):
            self.logger.error("Dataset validation failed!")
            return None

        self.logger.info("Starting model training...")

        try:
            ml_system = DDoSMLModels()
            results = ml_system.train_all_models(dataset_path)

            # Verify models were saved
            model_files = [
                '/app/models/random_forest_model.pkl',
                '/app/models/decision_tree_model.pkl',
                '/app/models/k-nn_model.pkl',
                '/app/models/svm_model.pkl',
                '/app/models/mlp_model.pkl',
                '/app/models/dnn_model.h5',
                '/app/models/scaler.pkl'
            ]

            saved_models = []
            for model_file in model_files:
                if os.path.exists(model_file):
                    saved_models.append(os.path.basename(model_file))

            self.logger.info(f"Models saved successfully: {saved_models}")
            self.logger.info("Model training completed!")

            return results

        except Exception as e:
            self.logger.error(f"Error during model training: {e}")
            return None

    def start_real_time_detection(self):
        """Start real-time detection system"""
        model_path = '/app/models/random_forest_model.pkl'
        scaler_path = '/app/models/scaler.pkl'

        if not (os.path.exists(model_path) and os.path.exists(scaler_path)):
            self.logger.error("Trained models not found! Please train models first.")
            return

        self.logger.info("Starting real-time detection system...")
        try:
            detector = RealTimeDetector(model_path, scaler_path)
            self.logger.info("Real-time detection system started successfully!")
            return detector
        except Exception as e:
            self.logger.error(f"Error starting real-time detection: {e}")
            return None

    def run_full_pipeline(self):
        """Run the complete DDoS detection pipeline"""
        self.running = True

        try:
            # Setup environment
            if not self.setup_environment():
                self.logger.error("Environment setup failed!")
                return

            # Collect training data
            dataset_path = self.collect_training_data(duration=300)  # 5 minutes for demo

            if dataset_path:
                # Train models
                results = self.train_models(dataset_path)

                if results:
                    self.logger.info("\n=== TRAINING RESULTS ===")
                    for model_name, result in results.items():
                        self.logger.info(f"{model_name}: {result['accuracy']:.4f}")

                    # Start real-time detection
                    detector = self.start_real_time_detection()

                    if detector:
                        self.logger.info("Pipeline completed successfully!")
                    else:
                        self.logger.warning("Real-time detection failed to start")
                else:
                    self.logger.error("Model training failed!")
            else:
                self.logger.error("Data collection failed!")

            # Don't run indefinitely after completion
            self.logger.info("System pipeline completed. Shutting down gracefully.")

        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal. Shutting down...")
        except Exception as e:
            self.logger.error(f"Unexpected error in pipeline: {e}")
        finally:
            self.cleanup()

    def cleanup(self):
        """Clean up resources"""
        self.logger.info("Starting cleanup...")
        self.running = False

        if self.traffic_generator:
            self.traffic_generator.is_running = False

        if self.topology:
            self.topology.cleanup()

        # Kill any remaining background processes
        try:
            subprocess.run(['pkill', '-f', 'hping3'], check=False)
            subprocess.run(['pkill', '-f', 'ping'], check=False)
        except:
            pass

        self.logger.info("Cleanup completed!")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print(f"\nReceived signal {signum}. Shutting down gracefully...")
    sys.exit(0)

if __name__ == "__main__":
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run the system
    system = DDoSDetectionSystem()
    system.run_full_pipeline()
