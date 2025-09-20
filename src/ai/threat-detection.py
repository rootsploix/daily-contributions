#!/usr/bin/env python3
# 🔥 RootsploiX AI-Powered Threat Detection Engine
# Advanced machine learning cybersecurity threat analysis

import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from datetime import datetime
import json

class AIThreatDetector:
    """
    Advanced AI-powered threat detection using machine learning algorithms.
    Combines neural networks and ensemble methods for maximum accuracy.
    """
    
    def __init__(self):
        self.version = "4.5.0"
        self.model_accuracy = 0.0
        self.neural_network = None
        self.random_forest = None
        self.threat_patterns = self._load_threat_patterns()
        
        print("🤖 AI Threat Detection Engine Initialized")
        print(f"📊 Version: {self.version}")
        
    def _load_threat_patterns(self):
        """Load comprehensive threat pattern database"""
        return {
            'sql_injection': [
                "' OR '1'='1", "UNION SELECT", "DROP TABLE",
                "; INSERT INTO", "'; DROP DATABASE", "admin'--",
                "' HAVING 1=1 --", "' AND 1=1 --"
            ],
            'xss_attack': [
                "<script>alert(", "javascript:", "onerror=",
                "onload=", "<iframe src=", "eval(",
                "document.cookie", "<img src=x onerror="
            ],
            'command_injection': [
                "; ls", "| cat", "&& whoami", "$(id)",
                "`uname -a`", "; wget", "| curl",
                "&& echo", "; nc -l"
            ],
            'directory_traversal': [
                "../../../etc/passwd", "..\\windows\\system32",
                "....//", "..%2f", "%2e%2e%2f",
                "..%c0%af", "..%252f"
            ],
            'buffer_overflow': [
                "A" * 1000, "\x90" * 100, "\x41" * 500,
                "shellcode", "nop sled", "ret2libc"
            ]
        }
    
    def train_neural_network(self, training_data=None):
        """Train deep neural network for threat detection"""
        print("🧠 Training Neural Network for Threat Detection...")
        
        if training_data is None:
            training_data = self._generate_training_data()
        
        # Create neural network architecture
        self.neural_network = tf.keras.Sequential([
            tf.keras.layers.Dense(128, activation='relu', input_shape=(100,)),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(5, activation='softmax')  # 5 threat categories
        ])
        
        self.neural_network.compile(
            optimizer='adam',
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
        # Train the model
        X_train, X_test, y_train, y_test = training_data
        
        history = self.neural_network.fit(
            X_train, y_train,
            epochs=50,
            batch_size=32,
            validation_split=0.2,
            verbose=0
        )
        
        # Evaluate model
        test_loss, test_accuracy = self.neural_network.evaluate(X_test, y_test, verbose=0)
        self.model_accuracy = test_accuracy
        
        print(f"✅ Neural Network Training Complete")
        print(f"🎯 Model Accuracy: {test_accuracy:.2%}")
        
        return history
    
    def train_ensemble_model(self, training_data=None):
        """Train Random Forest ensemble for threat classification"""
        print("🌲 Training Random Forest Ensemble...")
        
        if training_data is None:
            training_data = self._generate_training_data()
        
        X_train, X_test, y_train, y_test = training_data
        
        # Convert categorical to numerical for Random Forest
        y_train_numerical = np.argmax(y_train, axis=1)
        y_test_numerical = np.argmax(y_test, axis=1)
        
        self.random_forest = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            random_state=42
        )
        
        self.random_forest.fit(X_train, y_train_numerical)
        
        # Evaluate ensemble
        ensemble_accuracy = self.random_forest.score(X_test, y_test_numerical)
        
        print(f"✅ Random Forest Training Complete")
        print(f"🎯 Ensemble Accuracy: {ensemble_accuracy:.2%}")
        
        return ensemble_accuracy
    
    def _generate_training_data(self, samples=5000):
        """Generate synthetic training data for threat detection"""
        print("📊 Generating synthetic training data...")
        
        X = np.random.rand(samples, 100)  # Feature vectors
        y = np.zeros((samples, 5))  # One-hot encoded labels
        
        # Assign random threat categories
        for i in range(samples):
            category = np.random.randint(0, 5)
            y[i][category] = 1
        
        return train_test_split(X, y, test_size=0.2, random_state=42)
    
    def detect_threats(self, input_data):
        """Comprehensive threat detection using AI models"""
        threats_detected = []
        
        # Pattern-based detection
        pattern_threats = self._pattern_based_detection(input_data)
        threats_detected.extend(pattern_threats)
        
        # Neural network prediction
        if self.neural_network:
            nn_threats = self._neural_network_detection(input_data)
            threats_detected.extend(nn_threats)
        
        # Ensemble prediction
        if self.random_forest:
            ensemble_threats = self._ensemble_detection(input_data)
            threats_detected.extend(ensemble_threats)
        
        return self._consolidate_threats(threats_detected)
    
    def _pattern_based_detection(self, input_data):
        """Traditional pattern matching for known threats"""
        threats = []
        input_lower = input_data.lower()
        
        for threat_type, patterns in self.threat_patterns.items():
            for pattern in patterns:
                if pattern.lower() in input_lower:
                    threats.append({
                        'type': threat_type,
                        'method': 'pattern_matching',
                        'confidence': 0.95,
                        'pattern': pattern,
                        'timestamp': datetime.now().isoformat()
                    })
        
        return threats
    
    def _neural_network_detection(self, input_data):
        """AI neural network threat prediction"""
        if not self.neural_network:
            return []
        
        # Convert input to feature vector (simplified)
        features = np.array([hash(char) % 100 for char in input_data[:100]])
        if len(features) < 100:
            features = np.pad(features, (0, 100 - len(features)), 'constant')
        
        features = features.reshape(1, -1) / 100.0  # Normalize
        
        prediction = self.neural_network.predict(features, verbose=0)
        max_confidence = np.max(prediction)
        predicted_class = np.argmax(prediction)
        
        threat_classes = ['sql_injection', 'xss_attack', 'command_injection', 
                         'directory_traversal', 'buffer_overflow']
        
        if max_confidence > 0.7:  # High confidence threshold
            return [{
                'type': threat_classes[predicted_class],
                'method': 'neural_network',
                'confidence': float(max_confidence),
                'model_version': self.version,
                'timestamp': datetime.now().isoformat()
            }]
        
        return []
    
    def _ensemble_detection(self, input_data):
        """Random Forest ensemble threat prediction"""
        if not self.random_forest:
            return []
        
        # Convert input to feature vector
        features = np.array([hash(char) % 100 for char in input_data[:100]])
        if len(features) < 100:
            features = np.pad(features, (0, 100 - len(features)), 'constant')
        
        features = features.reshape(1, -1)
        
        prediction = self.random_forest.predict_proba(features)[0]
        predicted_class = self.random_forest.predict(features)[0]
        max_confidence = np.max(prediction)
        
        threat_classes = ['sql_injection', 'xss_attack', 'command_injection',
                         'directory_traversal', 'buffer_overflow']
        
        if max_confidence > 0.6:  # Ensemble confidence threshold
            return [{
                'type': threat_classes[predicted_class],
                'method': 'random_forest',
                'confidence': float(max_confidence),
                'feature_importance': float(np.mean(self.random_forest.feature_importances_)),
                'timestamp': datetime.now().isoformat()
            }]
        
        return []
    
    def _consolidate_threats(self, threats):
        """Consolidate and rank detected threats"""
        if not threats:
            return []
        
        # Group by threat type
        threat_groups = {}
        for threat in threats:
            threat_type = threat['type']
            if threat_type not in threat_groups:
                threat_groups[threat_type] = []
            threat_groups[threat_type].append(threat)
        
        # Consolidate each group
        consolidated = []
        for threat_type, group in threat_groups.items():
            max_confidence = max(t['confidence'] for t in group)
            methods = [t['method'] for t in group]
            
            consolidated.append({
                'type': threat_type,
                'confidence': max_confidence,
                'detection_methods': methods,
                'severity': self._calculate_severity(threat_type, max_confidence),
                'recommendation': self._get_mitigation(threat_type),
                'timestamp': datetime.now().isoformat()
            })
        
        return sorted(consolidated, key=lambda x: x['confidence'], reverse=True)
    
    def _calculate_severity(self, threat_type, confidence):
        """Calculate threat severity based on type and confidence"""
        severity_map = {
            'sql_injection': 'CRITICAL',
            'command_injection': 'CRITICAL', 
            'buffer_overflow': 'HIGH',
            'xss_attack': 'HIGH',
            'directory_traversal': 'MEDIUM'
        }
        
        base_severity = severity_map.get(threat_type, 'MEDIUM')
        
        if confidence > 0.9:
            return base_severity
        elif confidence > 0.7:
            levels = {'CRITICAL': 'HIGH', 'HIGH': 'MEDIUM', 'MEDIUM': 'LOW'}
            return levels.get(base_severity, 'LOW')
        else:
            return 'LOW'
    
    def _get_mitigation(self, threat_type):
        """Get mitigation recommendations for threat types"""
        mitigations = {
            'sql_injection': 'Use parameterized queries and input validation',
            'xss_attack': 'Implement Content Security Policy and output encoding',
            'command_injection': 'Validate and sanitize all user inputs',
            'directory_traversal': 'Use absolute paths and input validation',
            'buffer_overflow': 'Use bounds checking and memory-safe languages'
        }
        return mitigations.get(threat_type, 'Apply security best practices')
    
    def generate_ai_report(self):
        """Generate comprehensive AI threat detection report"""
        return {
            'ai_threat_detector': {
                'version': self.version,
                'timestamp': datetime.now().isoformat(),
                'model_performance': {
                    'neural_network_accuracy': self.model_accuracy,
                    'ensemble_accuracy': getattr(self, 'ensemble_accuracy', 0.0),
                    'threat_patterns_loaded': len(self.threat_patterns),
                    'total_patterns': sum(len(patterns) for patterns in self.threat_patterns.values())
                },
                'capabilities': [
                    'Real-time threat detection',
                    'Neural network classification',
                    'Random Forest ensemble learning',
                    'Pattern-based threat matching',
                    'Multi-method threat consolidation'
                ],
                'supported_threats': list(self.threat_patterns.keys()),
                'detection_methods': ['pattern_matching', 'neural_network', 'random_forest']
            }
        }

def main():
    """Demonstrate AI threat detection capabilities"""
    print("🔥 RootsploiX AI Threat Detection Demo")
    print("=" * 45)
    
    # Initialize AI detector
    detector = AIThreatDetector()
    
    # Train AI models
    detector.train_neural_network()
    detector.train_ensemble_model()
    
    # Test threat detection
    test_inputs = [
        "' OR '1'='1 --",
        "<script>alert('XSS')</script>",
        "; rm -rf /",
        "../../../etc/passwd",
        "SELECT * FROM users WHERE id = 1"
    ]
    
    print("\n🔍 Testing AI Threat Detection:")
    print("-" * 35)
    
    for i, test_input in enumerate(test_inputs, 1):
        print(f"\n{i}. Input: {test_input}")
        threats = detector.detect_threats(test_input)
        
        if threats:
            for threat in threats:
                print(f"   ⚠️ {threat['type']} ({threat['severity']})")
                print(f"   🎯 Confidence: {threat['confidence']:.2%}")
                print(f"   🔧 Methods: {', '.join(threat['detection_methods'])}")
        else:
            print("   ✅ No threats detected")
    
    # Generate report
    report = detector.generate_ai_report()
    
    print(f"\n📊 AI Model Performance:")
    print(f"   Neural Network: {detector.model_accuracy:.2%}")
    print(f"   Threat Patterns: {sum(len(p) for p in detector.threat_patterns.values())}")
    
    # Save report
    with open('ai_threat_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("\n✅ AI threat detection demo complete!")
    print("📄 Report saved to: ai_threat_report.json")

if __name__ == "__main__":
    main()