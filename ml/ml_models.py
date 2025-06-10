#!/usr/bin/env python3

import pandas as pd
import numpy as np
import logging
import os
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_curve, auc
import tensorflow as tf
from tensorflow import keras
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

# Setup logging
logging.basicConfig(level=logging.INFO)

class DDoSMLModels:
    def __init__(self):
        self.models = {}
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = []
        self.logger = logging.getLogger(__name__)

    def load_and_preprocess_data(self, csv_file):
        """Load and preprocess the dataset"""
        self.logger.info("Loading dataset...")

        try:
            df = pd.read_csv(csv_file)
            self.logger.info(f"Dataset loaded: {df.shape}")
        except Exception as e:
            self.logger.error(f"Error loading dataset: {e}")
            raise

        # Handle missing values
        df = df.fillna(0)

        # Encode categorical features
        categorical_columns = ['src_ip', 'dst_ip']
        for col in categorical_columns:
            if col in df.columns:
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str))

        # Separate features and target
        feature_columns = [col for col in df.columns if col not in [
            'label', 'src_ip', 'dst_ip', 'switch_id', 'dt', 'port_num'
        ]]
        self.feature_columns = feature_columns

        self.logger.info(f"Using {len(feature_columns)} features: {feature_columns}")

        X = df[feature_columns]
        y = df['label']

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        self.logger.info(f"Dataset shape: {X.shape}")
        self.logger.info(f"Benign samples: {sum(y == 0)}")
        self.logger.info(f"Malicious samples: {sum(y == 1)}")

        return X_scaled, y, df

    def train_traditional_models(self, X_train, y_train):
        """Train traditional ML models"""
        self.logger.info("Training traditional ML models...")

        models_to_train = {
            'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
            'Decision Tree': DecisionTreeClassifier(random_state=42),
            'K-NN': KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
            'SVM': SVC(kernel='rbf', random_state=42, probability=True),
            'MLP': MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=500, random_state=42)
        }

        for name, model in models_to_train.items():
            try:
                self.logger.info(f"Training {name}...")
                model.fit(X_train, y_train)
                self.models[name] = model
                self.logger.info(f"{name} training completed")
            except Exception as e:
                self.logger.error(f"Error training {name}: {e}")

    def create_dnn_model(self, input_dim):
        """Create Deep Neural Network model"""
        model = keras.Sequential([
            keras.layers.Dense(128, activation='relu', input_shape=(input_dim,)),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(64, activation='relu'),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(32, activation='relu'),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(16, activation='relu'),
            keras.layers.Dense(1, activation='sigmoid')
        ])

        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )

        return model

    def train_dnn_model(self, X_train, y_train, X_val, y_val):
        """Train Deep Neural Network"""
        self.logger.info("Training Deep Neural Network...")

        try:
            model = self.create_dnn_model(X_train.shape[1])

            # Training callbacks
            early_stopping = keras.callbacks.EarlyStopping(
                monitor='val_loss', patience=10, restore_best_weights=True
            )

            reduce_lr = keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss', factor=0.2, patience=5, min_lr=0.001
            )

            # Train model
            history = model.fit(
                X_train, y_train,
                batch_size=32,
                epochs=100,
                validation_data=(X_val, y_val),
                callbacks=[early_stopping, reduce_lr],
                verbose=1
            )

            self.models['DNN'] = model
            self.logger.info("DNN training completed")
            return history

        except Exception as e:
            self.logger.error(f"Error training DNN: {e}")
            return None

    def evaluate_models(self, X_test, y_test):
        """Evaluate all trained models"""
        self.logger.info("Evaluating models...")
        results = {}

        for name, model in self.models.items():
            try:
                y_pred_proba = None
                if name == 'DNN':
                    y_pred_prob_dnn = model.predict(X_test)
                    y_pred = (y_pred_prob_dnn > 0.5).astype(int).flatten()
                    y_pred_proba = y_pred_prob_dnn.flatten()
                else: # Traditional ML
                    y_pred = model.predict(X_test)
                    if hasattr(model, 'predict_proba'):
                        y_pred_proba = model.predict_proba(X_test)[:, 1]

                # Calculate metrics
                accuracy = accuracy_score(y_test, y_pred)
                report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

                results[name] = {
                    'accuracy': accuracy,
                    'predictions': y_pred,
                    'probabilities': y_pred_proba,
                    'classification_report': report,
                    'confusion_matrix': confusion_matrix(y_test, y_pred)
                }

                self.logger.info(f"\n{name} Results -> Accuracy: {accuracy:.4f}")

            except Exception as e:
                self.logger.error(f"Error evaluating {name}: {e}")
        return results

    def plot_all_results(self, results, y_test, history=None):
        """Plot comprehensive comparison results for all models."""
        self.logger.info("Generating all result visualizations...")
        os.makedirs('/app/models', exist_ok=True)

        # 1. Plot Perbandingan Metrik Kinerja (Accuracy, Precision, Recall, F1)
        try:
            metrics_data = {
                'Accuracy': [res['accuracy'] for res in results.values()],
                'Precision': [res['classification_report']['1']['precision'] for res in results.values()],
                'Recall': [res['classification_report']['1']['recall'] for res in results.values()],
                'F1-Score': [res['classification_report']['1']['f1-score'] for res in results.values()]
            }
            metrics_df = pd.DataFrame(metrics_data, index=results.keys())

            metrics_df.plot(kind='bar', figsize=(15, 8), colormap='viridis')
            plt.title('Model Performance Metrics Comparison')
            plt.ylabel('Score')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig('/app/models/1_performance_metrics.png')
            plt.close()
            self.logger.info("Saved performance metrics plot.")
        except Exception as e:
            self.logger.error(f"Error plotting performance metrics: {e}")

        # 2. Plot Semua Confusion Matrix
        try:
            num_models = len(results)
            fig, axes = plt.subplots(1, num_models, figsize=(5 * num_models, 4))
            fig.suptitle('Confusion Matrices for All Models', fontsize=16)
            for i, (name, res) in enumerate(results.items()):
                ax = axes[i]
                sns.heatmap(res['confusion_matrix'], annot=True, fmt='d', cmap='Blues', ax=ax)
                ax.set_title(name)
                ax.set_xlabel('Predicted')
                ax.set_ylabel('Actual')
            plt.tight_layout(rect=[0, 0, 1, 0.96])
            plt.savefig('/app/models/2_all_confusion_matrices.png')
            plt.close()
            self.logger.info("Saved all confusion matrices plot.")
        except Exception as e:
            self.logger.error(f"Error plotting confusion matrices: {e}")

        # 3. Plot Feature Importance (dari Random Forest)
        try:
            if 'Random Forest' in self.models:
                rf_model = self.models['Random Forest']
                importances = rf_model.feature_importances_
                feature_names = self.feature_columns
                feature_importance_df = pd.DataFrame({'feature': feature_names, 'importance': importances})
                feature_importance_df = feature_importance_df.sort_values('importance', ascending=False)

                plt.figure(figsize=(10, 8))
                sns.barplot(x='importance', y='feature', data=feature_importance_df)
                plt.title('Feature Importance from Random Forest')
                plt.tight_layout()
                plt.savefig('/app/models/3_feature_importance.png')
                plt.close()
                self.logger.info("Saved feature importance plot.")
        except Exception as e:
            self.logger.error(f"Error plotting feature importance: {e}")

        # 4. Plot ROC Curves
        try:
            plt.figure(figsize=(10, 8))
            for name, res in results.items():
                if res['probabilities'] is not None:
                    fpr, tpr, _ = roc_curve(y_test, res['probabilities'])
                    roc_auc = auc(fpr, tpr)
                    plt.plot(fpr, tpr, label=f'{name} (AUC = {roc_auc:.2f})')

            plt.plot([0, 1], [0, 1], 'k--')
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title('Receiver Operating Characteristic (ROC) Curves')
            plt.legend(loc="lower right")
            plt.savefig('/app/models/4_roc_curves.png')
            plt.close()
            self.logger.info("Saved ROC curves plot.")
        except Exception as e:
            import traceback
            self.logger.error("!!! FAILED TO PLOT ROC CURVE !!!")
            self.logger.error(f"Error type: {type(e).__name__}, Message: {e}")
            traceback.print_exc()

        # 5. Plot DNN Training History (jika ada)
        if history:
            try:
                plt.figure(figsize=(12, 5))

                # Plot Akurasi
                plt.subplot(1, 2, 1)
                plt.plot(history.history['accuracy'], label='Training Accuracy')
                plt.plot(history.history['val_accuracy'], label='Validation Accuracy')
                plt.title('DNN Accuracy over Epochs')
                plt.xlabel('Epoch')
                plt.ylabel('Accuracy')
                plt.legend()

                # Plot Loss
                plt.subplot(1, 2, 2)
                plt.plot(history.history['loss'], label='Training Loss')
                plt.plot(history.history['val_loss'], label='Validation Loss')
                plt.title('DNN Loss over Epochs')
                plt.xlabel('Epoch')
                plt.ylabel('Loss')
                plt.legend()

                plt.tight_layout()
                plt.savefig('/app/models/5_dnn_training_history.png')
                plt.close()
                self.logger.info("Saved DNN training history plot.")
            except Exception as e:
                self.logger.error(f"Error plotting DNN history: {e}")

    def save_models(self, results):
        """Save trained models"""
        self.logger.info("Saving models...")
        os.makedirs('/app/models', exist_ok=True)

        best_model_name = None
        best_accuracy = 0.0

        # Save traditional ML models and find the best one
        for name, model in self.models.items():
            if name != 'DNN':
                try:
                    filename = f'/app/models/{name.lower().replace(" ", "_").replace("-", "_")}_model.pkl'
                    joblib.dump(model, filename)
                    self.logger.info(f"Saved {name} model to {filename}")

                    # Cek apakah model ini yang terbaik sejauh ini
                    if name in results and results[name]['accuracy'] > best_accuracy:
                        best_accuracy = results[name]['accuracy']
                        best_model_name = name

                except Exception as e:
                    self.logger.error(f"Error saving {name}: {e}")

        # Save a copy of the best model as 'best_model.pkl'
        if best_model_name:
            self.logger.info(f"Best performing model is {best_model_name} with accuracy {best_accuracy:.4f}.")
            best_model_filename = f'/app/models/{best_model_name.lower().replace(" ", "_").replace("-", "_")}_model.pkl'
            best_model_copy_path = '/app/models/best_model.pkl'
            # Copy file
            import shutil
            shutil.copyfile(best_model_filename, best_model_copy_path)
            self.logger.info(f"Copied best model to {best_model_copy_path}.")

        # Save DNN model
        if 'DNN' in self.models:
            self.models['DNN'].save('/app/models/dnn_model.h5')
            self.logger.info("Saved DNN model")

        # Save preprocessors
        joblib.dump(self.scaler, '/app/models/scaler.pkl')
        self.logger.info("Saved scaler")

    def train_all_models(self, csv_file):
        """Complete training pipeline"""
        try:
            # Load and preprocess data
            X, y, df = self.load_and_preprocess_data(csv_file)

            # Split data
            X_train, X_temp, y_train, y_temp = train_test_split(
                X, y, test_size=0.4, random_state=42, stratify=y
            )
            X_val, X_test, y_val, y_test = train_test_split(
                X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
            )

            self.logger.info(f"Training set: {X_train.shape[0]} samples")
            self.logger.info(f"Validation set: {X_val.shape[0]} samples")
            self.logger.info(f"Test set: {X_test.shape[0]} samples")

            # Train traditional models
            self.train_traditional_models(X_train, y_train)

            # Train DNN
            dnn_history = self.train_dnn_model(X_train, y_train, X_val, y_val)

            # Evaluate models
            results = self.evaluate_models(X_test, y_test)

            # Plot results (pass y_test as parameter)
            self.plot_all_results(results, y_test, history=dnn_history)

            # Save models
            self.save_models(results)

            return results

        except Exception as e:
            self.logger.error(f"Error in training pipeline: {e}")
            return None

class RealTimeDetector:
    """Real-time DDoS detection system"""

    def __init__(self, model_path, scaler_path):
        self.logger = logging.getLogger(__name__)

        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.threshold = 0.5
            self.logger.info("Real-time detector initialized successfully")
        except Exception as e:
            self.logger.error(f"Error initializing detector: {e}")
            raise

    def predict(self, features):
        """Predict if traffic is malicious"""
        try:
            # Scale features
            features_scaled = self.scaler.transform([features])

            # Make prediction
            if hasattr(self.model, 'predict_proba'):
                prob = self.model.predict_proba(features_scaled)[0][1]
                prediction = 1 if prob > self.threshold else 0
            else:
                prediction = self.model.predict(features_scaled)[0]
                prob = prediction

            return prediction, prob

        except Exception as e:
            self.logger.error(f"Error making prediction: {e}")
            return 0, 0.0
