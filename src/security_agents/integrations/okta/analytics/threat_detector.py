"""
AI-Powered Threat Detection for Okta Security

Machine learning-based threat detection using behavioral analytics,
anomaly detection, and pattern recognition for identity threats.
"""

import pickle
import json
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import os
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import structlog

from ..okta_security.exceptions import ThreatDetectionError

logger = structlog.get_logger()


@dataclass
class ThreatAlert:
    """Represents a detected threat"""
    alert_id: str
    threat_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float
    description: str
    affected_users: List[str]
    indicators: List[str]
    events: List[Dict]
    timestamp: datetime
    ml_features: Dict
    recommended_actions: List[str]


@dataclass
class UserProfile:
    """Behavioral profile for a user"""
    user_id: str
    created_date: datetime
    login_patterns: Dict
    location_patterns: Dict
    application_usage: Dict
    time_patterns: Dict
    device_patterns: Dict
    risk_score: float = 0.0
    last_updated: datetime = None


class FeatureExtractor:
    """Extract features from Okta events for ML analysis"""
    
    def __init__(self):
        self.label_encoders = {}
        self.feature_cache = {}
    
    def extract_event_features(self, event: Dict) -> Dict:
        """Extract features from a single event"""
        features = {}
        
        # Basic event features
        features['event_type'] = event.get('eventType', 'unknown')
        features['severity'] = event.get('severity', 'INFO')
        features['outcome_result'] = event.get('outcome', {}).get('result', 'UNKNOWN')
        
        # Actor features
        actor = event.get('actor', {})
        features['actor_type'] = actor.get('type', 'unknown')
        features['actor_id'] = actor.get('id', 'unknown')
        
        # Client features
        client = event.get('client', {})
        features['client_ip'] = client.get('ipAddress', '0.0.0.0')
        features['user_agent'] = client.get('userAgent', {}).get('rawUserAgent', '')
        features['device'] = client.get('device', 'unknown')
        
        # Geographic features
        geo = client.get('geographicalContext', {})
        features['country'] = geo.get('country', 'unknown')
        features['state'] = geo.get('state', 'unknown')
        features['city'] = geo.get('city', 'unknown')
        features['postal_code'] = geo.get('postalCode', 'unknown')
        
        # Time features
        published = datetime.fromisoformat(event['published'].replace('Z', '+00:00'))
        features['hour'] = published.hour
        features['day_of_week'] = published.weekday()
        features['is_weekend'] = published.weekday() >= 5
        features['is_business_hours'] = 9 <= published.hour <= 17
        
        # Target features
        targets = event.get('target', [])
        features['target_count'] = len(targets)
        features['target_types'] = [t.get('type', 'unknown') for t in targets]
        
        # Authentication context
        auth_context = event.get('authenticationContext', {})
        features['auth_provider'] = auth_context.get('authenticationProvider', 'unknown')
        features['auth_step'] = auth_context.get('authenticationStep', 0)
        
        # Security context
        security_context = event.get('securityContext', {})
        features['as_number'] = security_context.get('asNumber', 0)
        features['as_org'] = security_context.get('asOrg', 'unknown')
        features['is_proxy'] = security_context.get('isProxy', False)
        
        return features
    
    def extract_user_session_features(self, events: List[Dict]) -> Dict:
        """Extract aggregate features from user session events"""
        if not events:
            return {}
        
        features = {}
        
        # Session duration and event count
        if len(events) > 1:
            start_time = datetime.fromisoformat(events[0]['published'].replace('Z', '+00:00'))
            end_time = datetime.fromisoformat(events[-1]['published'].replace('Z', '+00:00'))
            features['session_duration_minutes'] = (end_time - start_time).total_seconds() / 60
        else:
            features['session_duration_minutes'] = 0
        
        features['event_count'] = len(events)
        
        # Event type distribution
        event_types = [e.get('eventType', 'unknown') for e in events]
        type_counts = Counter(event_types)
        features['unique_event_types'] = len(type_counts)
        features['most_common_event_type'] = type_counts.most_common(1)[0][0] if type_counts else 'unknown'
        
        # Outcome analysis
        outcomes = [e.get('outcome', {}).get('result', 'UNKNOWN') for e in events]
        outcome_counts = Counter(outcomes)
        features['failure_rate'] = outcome_counts.get('FAILURE', 0) / len(outcomes)
        features['success_rate'] = outcome_counts.get('SUCCESS', 0) / len(outcomes)
        
        # Geographic diversity
        countries = set()
        ips = set()
        user_agents = set()
        
        for event in events:
            client = event.get('client', {})
            geo = client.get('geographicalContext', {})
            if geo.get('country'):
                countries.add(geo['country'])
            if client.get('ipAddress'):
                ips.add(client['ipAddress'])
            if client.get('userAgent', {}).get('rawUserAgent'):
                user_agents.add(client['userAgent']['rawUserAgent'])
        
        features['unique_countries'] = len(countries)
        features['unique_ips'] = len(ips)
        features['unique_user_agents'] = len(user_agents)
        
        # Time pattern analysis
        hours = [datetime.fromisoformat(e['published'].replace('Z', '+00:00')).hour for e in events]
        features['hour_variance'] = np.var(hours) if hours else 0
        features['spans_business_hours'] = any(9 <= h <= 17 for h in hours)
        features['spans_weekend'] = any(datetime.fromisoformat(e['published'].replace('Z', '+00:00')).weekday() >= 5 for e in events)
        
        return features
    
    def encode_categorical_features(self, features_df: pd.DataFrame) -> pd.DataFrame:
        """Encode categorical features for ML"""
        categorical_cols = [
            'event_type', 'severity', 'outcome_result', 'actor_type',
            'device', 'country', 'state', 'auth_provider', 'as_org',
            'most_common_event_type'
        ]
        
        for col in categorical_cols:
            if col in features_df.columns:
                if col not in self.label_encoders:
                    self.label_encoders[col] = LabelEncoder()
                    features_df[f'{col}_encoded'] = self.label_encoders[col].fit_transform(features_df[col].fillna('unknown'))
                else:
                    # Handle unseen categories
                    unique_values = set(features_df[col].fillna('unknown'))
                    known_values = set(self.label_encoders[col].classes_)
                    new_values = unique_values - known_values
                    
                    if new_values:
                        # Extend encoder with new categories
                        all_values = list(known_values) + list(new_values)
                        self.label_encoders[col].classes_ = np.array(all_values)
                    
                    features_df[f'{col}_encoded'] = self.label_encoders[col].transform(features_df[col].fillna('unknown'))
        
        return features_df


class UserBehaviorAnalyzer:
    """Analyze and model user behavior patterns"""
    
    def __init__(self):
        self.user_profiles: Dict[str, UserProfile] = {}
        self.baseline_window = timedelta(days=30)
    
    def build_user_profile(self, user_id: str, events: List[Dict]) -> UserProfile:
        """Build behavioral profile for user"""
        if not events:
            return UserProfile(
                user_id=user_id,
                created_date=datetime.utcnow(),
                login_patterns={},
                location_patterns={},
                application_usage={},
                time_patterns={},
                device_patterns={}
            )
        
        # Analyze login patterns
        login_events = [e for e in events if 'authentication' in e.get('eventType', '')]
        login_patterns = self._analyze_login_patterns(login_events)
        
        # Analyze location patterns
        location_patterns = self._analyze_location_patterns(events)
        
        # Analyze application usage
        app_usage = self._analyze_application_usage(events)
        
        # Analyze time patterns
        time_patterns = self._analyze_time_patterns(events)
        
        # Analyze device patterns
        device_patterns = self._analyze_device_patterns(events)
        
        profile = UserProfile(
            user_id=user_id,
            created_date=datetime.utcnow(),
            login_patterns=login_patterns,
            location_patterns=location_patterns,
            application_usage=app_usage,
            time_patterns=time_patterns,
            device_patterns=device_patterns,
            last_updated=datetime.utcnow()
        )
        
        # Calculate baseline risk score
        profile.risk_score = self._calculate_baseline_risk(profile)
        
        self.user_profiles[user_id] = profile
        return profile
    
    def _analyze_login_patterns(self, login_events: List[Dict]) -> Dict:
        """Analyze user's login behavior patterns"""
        if not login_events:
            return {'frequency': 0, 'success_rate': 0, 'common_methods': []}
        
        # Login frequency (logins per day)
        if len(login_events) > 1:
            start = datetime.fromisoformat(login_events[0]['published'].replace('Z', '+00:00'))
            end = datetime.fromisoformat(login_events[-1]['published'].replace('Z', '+00:00'))
            days = max((end - start).days, 1)
            frequency = len(login_events) / days
        else:
            frequency = 1
        
        # Success rate
        outcomes = [e.get('outcome', {}).get('result', 'UNKNOWN') for e in login_events]
        success_count = outcomes.count('SUCCESS')
        success_rate = success_count / len(outcomes) if outcomes else 0
        
        # Common authentication methods
        auth_methods = []
        for event in login_events:
            auth_context = event.get('authenticationContext', {})
            provider = auth_context.get('authenticationProvider', 'unknown')
            auth_methods.append(provider)
        
        common_methods = [method for method, count in Counter(auth_methods).most_common(3)]
        
        return {
            'frequency': frequency,
            'success_rate': success_rate,
            'common_methods': common_methods,
            'total_attempts': len(login_events),
            'failed_attempts': outcomes.count('FAILURE')
        }
    
    def _analyze_location_patterns(self, events: List[Dict]) -> Dict:
        """Analyze user's location patterns"""
        locations = []
        ips = []
        
        for event in events:
            client = event.get('client', {})
            geo = client.get('geographicalContext', {})
            
            if geo.get('country'):
                locations.append({
                    'country': geo.get('country'),
                    'state': geo.get('state'),
                    'city': geo.get('city')
                })
            
            if client.get('ipAddress'):
                ips.append(client['ipAddress'])
        
        # Most common locations
        location_strs = [f"{loc['country']}/{loc['state']}/{loc['city']}" for loc in locations]
        common_locations = [loc for loc, count in Counter(location_strs).most_common(5)]
        
        # IP diversity
        unique_ips = len(set(ips))
        
        return {
            'common_locations': common_locations,
            'unique_countries': len(set(loc['country'] for loc in locations if loc['country'])),
            'unique_ips': unique_ips,
            'total_locations': len(locations)
        }
    
    def _analyze_application_usage(self, events: List[Dict]) -> Dict:
        """Analyze user's application access patterns"""
        apps = []
        
        for event in events:
            targets = event.get('target', [])
            for target in targets:
                if target.get('type') == 'Application':
                    app_name = target.get('displayName', target.get('id', 'unknown'))
                    apps.append(app_name)
        
        app_counts = Counter(apps)
        common_apps = [app for app, count in app_counts.most_common(10)]
        
        return {
            'common_applications': common_apps,
            'unique_applications': len(set(apps)),
            'total_app_events': len(apps)
        }
    
    def _analyze_time_patterns(self, events: List[Dict]) -> Dict:
        """Analyze user's time-based activity patterns"""
        if not events:
            return {'common_hours': [], 'business_hours_ratio': 0, 'weekend_ratio': 0}
        
        hours = []
        is_business_hours = []
        is_weekend = []
        
        for event in events:
            timestamp = datetime.fromisoformat(event['published'].replace('Z', '+00:00'))
            hours.append(timestamp.hour)
            is_business_hours.append(9 <= timestamp.hour <= 17)
            is_weekend.append(timestamp.weekday() >= 5)
        
        # Most common activity hours
        hour_counts = Counter(hours)
        common_hours = [hour for hour, count in hour_counts.most_common(5)]
        
        # Business hours vs after hours ratio
        business_ratio = sum(is_business_hours) / len(is_business_hours)
        weekend_ratio = sum(is_weekend) / len(is_weekend)
        
        return {
            'common_hours': common_hours,
            'business_hours_ratio': business_ratio,
            'weekend_ratio': weekend_ratio,
            'hour_distribution': dict(hour_counts)
        }
    
    def _analyze_device_patterns(self, events: List[Dict]) -> Dict:
        """Analyze user's device and client patterns"""
        devices = []
        user_agents = []
        
        for event in events:
            client = event.get('client', {})
            if client.get('device'):
                devices.append(client['device'])
            
            ua = client.get('userAgent', {})
            if ua.get('rawUserAgent'):
                user_agents.append(ua['rawUserAgent'])
        
        device_counts = Counter(devices)
        ua_counts = Counter(user_agents)
        
        return {
            'common_devices': [dev for dev, count in device_counts.most_common(5)],
            'unique_devices': len(set(devices)),
            'common_user_agents': [ua for ua, count in ua_counts.most_common(3)],
            'unique_user_agents': len(set(user_agents))
        }
    
    def _calculate_baseline_risk(self, profile: UserProfile) -> float:
        """Calculate baseline risk score for user profile"""
        risk_score = 0.0
        
        # High failure rate is risky
        login_patterns = profile.login_patterns
        if login_patterns.get('success_rate', 1) < 0.8:
            risk_score += 20
        
        # Multiple locations/IPs indicate higher risk
        location_patterns = profile.location_patterns
        if location_patterns.get('unique_countries', 0) > 3:
            risk_score += 15
        if location_patterns.get('unique_ips', 0) > 10:
            risk_score += 10
        
        # Unusual time patterns
        time_patterns = profile.time_patterns
        if time_patterns.get('business_hours_ratio', 1) < 0.3:
            risk_score += 10  # Mostly after-hours activity
        if time_patterns.get('weekend_ratio', 0) > 0.5:
            risk_score += 5   # Lots of weekend activity
        
        # Device diversity
        device_patterns = profile.device_patterns
        if device_patterns.get('unique_devices', 0) > 5:
            risk_score += 10
        
        return min(risk_score, 100)
    
    def detect_anomalies(self, user_id: str, new_events: List[Dict]) -> List[Dict]:
        """Detect anomalies in user behavior"""
        anomalies = []
        
        if user_id not in self.user_profiles:
            logger.warning("No profile for user, building baseline", user_id=user_id)
            self.build_user_profile(user_id, new_events)
            return anomalies
        
        profile = self.user_profiles[user_id]
        
        # Check for location anomalies
        location_anomalies = self._detect_location_anomalies(profile, new_events)
        anomalies.extend(location_anomalies)
        
        # Check for time anomalies
        time_anomalies = self._detect_time_anomalies(profile, new_events)
        anomalies.extend(time_anomalies)
        
        # Check for device anomalies
        device_anomalies = self._detect_device_anomalies(profile, new_events)
        anomalies.extend(device_anomalies)
        
        # Check for login pattern anomalies
        login_anomalies = self._detect_login_anomalies(profile, new_events)
        anomalies.extend(login_anomalies)
        
        return anomalies
    
    def _detect_location_anomalies(self, profile: UserProfile, events: List[Dict]) -> List[Dict]:
        """Detect location-based anomalies"""
        anomalies = []
        known_locations = set(profile.location_patterns.get('common_locations', []))
        
        for event in events:
            client = event.get('client', {})
            geo = client.get('geographicalContext', {})
            
            if geo.get('country'):
                location_str = f"{geo.get('country')}/{geo.get('state')}/{geo.get('city')}"
                
                if location_str not in known_locations:
                    # Check if it's a completely new country
                    event_country = geo.get('country')
                    known_countries = [loc.split('/')[0] for loc in known_locations]
                    
                    if event_country not in known_countries:
                        anomalies.append({
                            'type': 'unknown_country',
                            'description': f'Login from unknown country: {event_country}',
                            'severity': 'HIGH',
                            'event': event,
                            'confidence': 0.9
                        })
                    else:
                        anomalies.append({
                            'type': 'unknown_location',
                            'description': f'Login from new location: {location_str}',
                            'severity': 'MEDIUM',
                            'event': event,
                            'confidence': 0.7
                        })
        
        return anomalies
    
    def _detect_time_anomalies(self, profile: UserProfile, events: List[Dict]) -> List[Dict]:
        """Detect time-based anomalies"""
        anomalies = []
        common_hours = set(profile.time_patterns.get('common_hours', []))
        business_ratio = profile.time_patterns.get('business_hours_ratio', 1)
        
        for event in events:
            timestamp = datetime.fromisoformat(event['published'].replace('Z', '+00:00'))
            hour = timestamp.hour
            is_weekend = timestamp.weekday() >= 5
            is_business_hours = 9 <= hour <= 17
            
            # Unusual hour detection
            if hour not in common_hours:
                # If user typically works business hours but this is way off
                if business_ratio > 0.8 and (hour < 6 or hour > 22):
                    anomalies.append({
                        'type': 'unusual_hour',
                        'description': f'Activity at unusual hour: {hour}:00',
                        'severity': 'MEDIUM',
                        'event': event,
                        'confidence': 0.6
                    })
            
            # Weekend activity for business-hours user
            if is_weekend and business_ratio > 0.9:
                anomalies.append({
                    'type': 'weekend_activity',
                    'description': 'Weekend activity for business-hours user',
                    'severity': 'LOW',
                    'event': event,
                    'confidence': 0.5
                })
        
        return anomalies
    
    def _detect_device_anomalies(self, profile: UserProfile, events: List[Dict]) -> List[Dict]:
        """Detect device-based anomalies"""
        anomalies = []
        known_devices = set(profile.device_patterns.get('common_devices', []))
        known_user_agents = set(profile.device_patterns.get('common_user_agents', []))
        
        for event in events:
            client = event.get('client', {})
            device = client.get('device', 'unknown')
            user_agent = client.get('userAgent', {}).get('rawUserAgent', '')
            
            # Unknown device
            if device != 'unknown' and device not in known_devices:
                anomalies.append({
                    'type': 'unknown_device',
                    'description': f'Login from unknown device: {device}',
                    'severity': 'MEDIUM',
                    'event': event,
                    'confidence': 0.7
                })
            
            # Unknown user agent
            if user_agent and user_agent not in known_user_agents:
                # Check if it's a completely different browser/OS
                if not any(ua in user_agent for ua in known_user_agents):
                    anomalies.append({
                        'type': 'unknown_user_agent',
                        'description': f'Login with unknown user agent pattern',
                        'severity': 'LOW',
                        'event': event,
                        'confidence': 0.5
                    })
        
        return anomalies
    
    def _detect_login_anomalies(self, profile: UserProfile, events: List[Dict]) -> List[Dict]:
        """Detect login pattern anomalies"""
        anomalies = []
        normal_frequency = profile.login_patterns.get('frequency', 1)
        
        # Count login events in new batch
        login_events = [e for e in events if 'authentication' in e.get('eventType', '')]
        
        # Unusual volume of login attempts
        if len(login_events) > normal_frequency * 10:  # 10x normal frequency
            anomalies.append({
                'type': 'high_login_volume',
                'description': f'Unusually high number of login attempts: {len(login_events)}',
                'severity': 'HIGH',
                'event': login_events[0] if login_events else None,
                'confidence': 0.8
            })
        
        # Multiple consecutive failures
        consecutive_failures = 0
        max_consecutive = 0
        
        for event in login_events:
            if event.get('outcome', {}).get('result') == 'FAILURE':
                consecutive_failures += 1
                max_consecutive = max(max_consecutive, consecutive_failures)
            else:
                consecutive_failures = 0
        
        if max_consecutive >= 5:
            anomalies.append({
                'type': 'consecutive_failures',
                'description': f'Multiple consecutive login failures: {max_consecutive}',
                'severity': 'HIGH',
                'event': login_events[0] if login_events else None,
                'confidence': 0.9
            })
        
        return anomalies


class ThreatDetector:
    """
    Advanced ML-based threat detection for Okta identity security.
    
    Combines supervised and unsupervised learning approaches to detect
    known and unknown threats in identity events.
    """
    
    def __init__(self, model_path: str = None):
        self.model_path = model_path or "models/"
        os.makedirs(self.model_path, exist_ok=True)
        
        # ML Models
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.classification_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        
        # Feature extraction and analysis
        self.feature_extractor = FeatureExtractor()
        self.behavior_analyzer = UserBehaviorAnalyzer()
        
        # Model state
        self.models_trained = False
        self.last_training_time = None
        
        # Threat detection cache
        self.alert_cache = {}
        
        logger.info("Threat detector initialized", model_path=self.model_path)
    
    def train_models(self, training_events: List[Dict], labels: List[str] = None):
        """Train ML models on historical data"""
        if not training_events:
            logger.warning("No training data provided")
            return
        
        logger.info("Training threat detection models", events=len(training_events))
        
        # Extract features
        features_list = []
        for event in training_events:
            features = self.feature_extractor.extract_event_features(event)
            features_list.append(features)
        
        # Convert to DataFrame
        features_df = pd.DataFrame(features_list)
        
        # Encode categorical features
        features_df = self.feature_extractor.encode_categorical_features(features_df)
        
        # Select numerical features for ML
        numerical_features = features_df.select_dtypes(include=[np.number]).fillna(0)
        
        # Scale features
        scaled_features = self.scaler.fit_transform(numerical_features)
        
        # Train anomaly detector (unsupervised)
        self.anomaly_detector.fit(scaled_features)
        
        # Train classification model if labels provided
        if labels:
            if len(labels) != len(training_events):
                logger.warning("Labels length doesn't match events length")
            else:
                X_train, X_test, y_train, y_test = train_test_split(
                    scaled_features, labels, test_size=0.2, random_state=42
                )
                
                self.classification_model.fit(X_train, y_train)
                
                # Evaluate model
                y_pred = self.classification_model.predict(X_test)
                report = classification_report(y_test, y_pred, output_dict=True)
                logger.info("Classification model trained", accuracy=report['accuracy'])
        
        # Save models
        self._save_models()
        
        self.models_trained = True
        self.last_training_time = datetime.utcnow()
        
        logger.info("Model training completed")
    
    def _save_models(self):
        """Save trained models to disk"""
        try:
            # Save anomaly detector
            with open(f"{self.model_path}/anomaly_detector.pkl", 'wb') as f:
                pickle.dump(self.anomaly_detector, f)
            
            # Save classification model
            with open(f"{self.model_path}/classification_model.pkl", 'wb') as f:
                pickle.dump(self.classification_model, f)
            
            # Save scaler
            with open(f"{self.model_path}/scaler.pkl", 'wb') as f:
                pickle.dump(self.scaler, f)
            
            # Save feature extractor
            with open(f"{self.model_path}/feature_extractor.pkl", 'wb') as f:
                pickle.dump(self.feature_extractor, f)
            
            logger.info("Models saved successfully")
            
        except Exception as e:
            logger.error("Failed to save models", error=str(e))
    
    def _load_models(self):
        """Load trained models from disk"""
        try:
            # Load anomaly detector
            with open(f"{self.model_path}/anomaly_detector.pkl", 'rb') as f:
                self.anomaly_detector = pickle.load(f)
            
            # Load classification model
            with open(f"{self.model_path}/classification_model.pkl", 'rb') as f:
                self.classification_model = pickle.load(f)
            
            # Load scaler
            with open(f"{self.model_path}/scaler.pkl", 'rb') as f:
                self.scaler = pickle.load(f)
            
            # Load feature extractor
            with open(f"{self.model_path}/feature_extractor.pkl", 'rb') as f:
                self.feature_extractor = pickle.load(f)
            
            self.models_trained = True
            logger.info("Models loaded successfully")
            
        except Exception as e:
            logger.warning("Failed to load models, using defaults", error=str(e))
    
    def detect_threats(self, events: List[Dict]) -> List[ThreatAlert]:
        """Detect threats in events using multiple analysis methods"""
        if not events:
            return []
        
        # Load models if not already loaded
        if not self.models_trained:
            self._load_models()
        
        threats = []
        
        try:
            # 1. ML-based anomaly detection
            ml_threats = self._detect_ml_anomalies(events)
            threats.extend(ml_threats)
            
            # 2. Behavioral analysis
            behavior_threats = self._detect_behavioral_anomalies(events)
            threats.extend(behavior_threats)
            
            # 3. Rule-based detection
            rule_threats = self._detect_rule_based_threats(events)
            threats.extend(rule_threats)
            
            # 4. Statistical anomalies
            stat_threats = self._detect_statistical_anomalies(events)
            threats.extend(stat_threats)
            
            # Deduplicate and prioritize
            threats = self._deduplicate_threats(threats)
            threats = sorted(threats, key=lambda x: (x.severity, x.confidence), reverse=True)
            
            logger.info("Threat detection completed", 
                       events_analyzed=len(events),
                       threats_found=len(threats))
            
        except Exception as e:
            logger.error("Threat detection failed", error=str(e))
            raise ThreatDetectionError(f"Threat detection failed: {e}")
        
        return threats
    
    def _detect_ml_anomalies(self, events: List[Dict]) -> List[ThreatAlert]:
        """Detect anomalies using ML models"""
        threats = []
        
        if not self.models_trained:
            return threats
        
        try:
            # Extract features
            features_list = []
            for event in events:
                features = self.feature_extractor.extract_event_features(event)
                features_list.append(features)
            
            features_df = pd.DataFrame(features_list)
            features_df = self.feature_extractor.encode_categorical_features(features_df)
            
            # Select numerical features
            numerical_features = features_df.select_dtypes(include=[np.number]).fillna(0)
            
            if len(numerical_features) == 0:
                return threats
            
            # Scale features
            scaled_features = self.scaler.transform(numerical_features)
            
            # Predict anomalies
            anomaly_scores = self.anomaly_detector.decision_function(scaled_features)
            anomaly_labels = self.anomaly_detector.predict(scaled_features)
            
            # Create alerts for anomalies
            for i, (event, score, is_anomaly) in enumerate(zip(events, anomaly_scores, anomaly_labels)):
                if is_anomaly == -1:  # Anomaly detected
                    confidence = min(abs(score) / 2.0, 1.0)  # Normalize score to confidence
                    
                    # Determine severity based on score
                    if abs(score) > 1.0:
                        severity = "HIGH"
                    elif abs(score) > 0.5:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                    
                    threat = ThreatAlert(
                        alert_id=f"ml_anomaly_{int(datetime.utcnow().timestamp())}_{i}",
                        threat_type="ML_Anomaly",
                        severity=severity,
                        confidence=confidence,
                        description=f"Machine learning anomaly detected (score: {score:.3f})",
                        affected_users=[event.get('actor', {}).get('id', 'unknown')],
                        indicators=[f"Anomaly score: {score:.3f}", "Statistical deviation from normal patterns"],
                        events=[event],
                        timestamp=datetime.utcnow(),
                        ml_features=features_list[i],
                        recommended_actions=["Investigate user activity", "Verify legitimacy", "Monitor closely"]
                    )
                    threats.append(threat)
                    
        except Exception as e:
            logger.error("ML anomaly detection failed", error=str(e))
        
        return threats
    
    def _detect_behavioral_anomalies(self, events: List[Dict]) -> List[ThreatAlert]:
        """Detect behavioral anomalies using user profiles"""
        threats = []
        
        # Group events by user
        user_events = defaultdict(list)
        for event in events:
            user_id = event.get('actor', {}).get('id')
            if user_id:
                user_events[user_id].append(event)
        
        # Analyze each user's behavior
        for user_id, user_event_list in user_events.items():
            anomalies = self.behavior_analyzer.detect_anomalies(user_id, user_event_list)
            
            for anomaly in anomalies:
                # Group related anomalies into single threat
                threat = ThreatAlert(
                    alert_id=f"behavior_anomaly_{user_id}_{int(datetime.utcnow().timestamp())}",
                    threat_type="Behavioral_Anomaly",
                    severity=anomaly['severity'],
                    confidence=anomaly['confidence'],
                    description=anomaly['description'],
                    affected_users=[user_id],
                    indicators=[anomaly['type'], anomaly['description']],
                    events=[anomaly['event']] if anomaly['event'] else [],
                    timestamp=datetime.utcnow(),
                    ml_features={'anomaly_type': anomaly['type']},
                    recommended_actions=["Review user activity", "Verify with user", "Update behavioral baseline"]
                )
                threats.append(threat)
        
        return threats
    
    def _detect_rule_based_threats(self, events: List[Dict]) -> List[ThreatAlert]:
        """Detect threats using predefined rules"""
        threats = []
        
        # Rule 1: Multiple failed logins
        failed_logins = defaultdict(list)
        for event in events:
            if (event.get('eventType') == 'user.authentication.auth_via_mfa' and
                event.get('outcome', {}).get('result') == 'FAILURE'):
                user_id = event.get('actor', {}).get('id')
                if user_id:
                    failed_logins[user_id].append(event)
        
        for user_id, failures in failed_logins.items():
            if len(failures) >= 10:  # 10+ failed attempts
                threat = ThreatAlert(
                    alert_id=f"brute_force_{user_id}_{int(datetime.utcnow().timestamp())}",
                    threat_type="Brute_Force_Attack",
                    severity="HIGH",
                    confidence=0.9,
                    description=f"Multiple failed login attempts detected: {len(failures)} failures",
                    affected_users=[user_id],
                    indicators=[f"{len(failures)} failed login attempts", "Potential brute force attack"],
                    events=failures[:10],  # Limit events
                    timestamp=datetime.utcnow(),
                    ml_features={'failure_count': len(failures)},
                    recommended_actions=["Block user account", "Investigate source IP", "Force password reset"]
                )
                threats.append(threat)
        
        # Rule 2: Admin actions outside business hours
        admin_events = [e for e in events if 'admin' in e.get('eventType', '').lower()]
        for event in admin_events:
            timestamp = datetime.fromisoformat(event['published'].replace('Z', '+00:00'))
            if timestamp.hour < 9 or timestamp.hour > 17 or timestamp.weekday() >= 5:
                threat = ThreatAlert(
                    alert_id=f"admin_after_hours_{int(datetime.utcnow().timestamp())}",
                    threat_type="Suspicious_Admin_Activity",
                    severity="MEDIUM",
                    confidence=0.6,
                    description="Administrative action performed outside business hours",
                    affected_users=[event.get('actor', {}).get('id', 'unknown')],
                    indicators=["After-hours admin activity", f"Time: {timestamp.strftime('%H:%M on %A')}"],
                    events=[event],
                    timestamp=datetime.utcnow(),
                    ml_features={'hour': timestamp.hour, 'day_of_week': timestamp.weekday()},
                    recommended_actions=["Verify admin action legitimacy", "Review admin permissions"]
                )
                threats.append(threat)
        
        return threats
    
    def _detect_statistical_anomalies(self, events: List[Dict]) -> List[ThreatAlert]:
        """Detect statistical anomalies in event patterns"""
        threats = []
        
        if len(events) < 10:  # Need sufficient data
            return threats
        
        # Analyze event frequency patterns
        event_times = []
        for event in events:
            timestamp = datetime.fromisoformat(event['published'].replace('Z', '+00:00'))
            event_times.append(timestamp)
        
        # Sort times and calculate intervals
        event_times.sort()
        intervals = []
        for i in range(1, len(event_times)):
            interval = (event_times[i] - event_times[i-1]).total_seconds()
            intervals.append(interval)
        
        if intervals:
            # Detect unusual bursts (very short intervals)
            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            
            burst_threshold = max(mean_interval - 2 * std_interval, 1)  # At least 1 second
            
            burst_count = sum(1 for interval in intervals if interval < burst_threshold)
            burst_ratio = burst_count / len(intervals)
            
            if burst_ratio > 0.5:  # More than 50% of events in bursts
                threat = ThreatAlert(
                    alert_id=f"event_burst_{int(datetime.utcnow().timestamp())}",
                    threat_type="Event_Burst",
                    severity="MEDIUM",
                    confidence=0.7,
                    description=f"Unusual burst of events detected: {burst_ratio:.1%} in rapid succession",
                    affected_users=list(set(e.get('actor', {}).get('id', 'unknown') for e in events)),
                    indicators=[f"Event burst ratio: {burst_ratio:.1%}", f"Mean interval: {mean_interval:.1f}s"],
                    events=events[:10],  # Sample of events
                    timestamp=datetime.utcnow(),
                    ml_features={'burst_ratio': burst_ratio, 'mean_interval': mean_interval},
                    recommended_actions=["Investigate event source", "Check for automated activity"]
                )
                threats.append(threat)
        
        return threats
    
    def _deduplicate_threats(self, threats: List[ThreatAlert]) -> List[ThreatAlert]:
        """Remove duplicate or similar threats"""
        if not threats:
            return threats
        
        # Group by threat type and affected users
        groups = defaultdict(list)
        for threat in threats:
            key = (threat.threat_type, tuple(sorted(threat.affected_users)))
            groups[key].append(threat)
        
        # Keep highest confidence threat from each group
        deduplicated = []
        for group in groups.values():
            if len(group) == 1:
                deduplicated.append(group[0])
            else:
                # Merge similar threats
                best_threat = max(group, key=lambda x: x.confidence)
                
                # Combine indicators and events
                all_indicators = []
                all_events = []
                for threat in group:
                    all_indicators.extend(threat.indicators)
                    all_events.extend(threat.events)
                
                best_threat.indicators = list(set(all_indicators))
                best_threat.events = all_events[:20]  # Limit events
                best_threat.description += f" (merged {len(group)} similar alerts)"
                
                deduplicated.append(best_threat)
        
        return deduplicated
    
    def get_threat_statistics(self) -> Dict:
        """Get threat detection statistics"""
        return {
            'models_trained': self.models_trained,
            'last_training_time': self.last_training_time.isoformat() if self.last_training_time else None,
            'user_profiles': len(self.behavior_analyzer.user_profiles),
            'cache_size': len(self.alert_cache)
        }