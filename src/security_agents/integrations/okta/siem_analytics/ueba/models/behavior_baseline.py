"""
UEBA Behavior Baseline Engine
Builds and maintains statistical baselines for user behavior patterns
"""

import json
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
import joblib
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class BehaviorFeatures:
    """User behavior feature representation"""
    user_id: str
    timestamp: datetime
    
    # Temporal features
    hour_of_day: int
    day_of_week: int
    is_weekend: bool
    is_business_hours: bool
    
    # Geographic features
    country: str
    city: str
    latitude: float
    longitude: float
    
    # Device/Network features
    device_type: str
    os_type: str
    browser_type: str
    ip_address: str
    network_zone: str
    
    # Application access features
    application_name: str
    authentication_method: str
    session_duration: int
    
    # Risk indicators
    is_new_device: bool
    is_new_location: bool
    failed_attempts_recent: int
    privilege_level: str


@dataclass
class BehaviorBaseline:
    """Statistical baseline for user behavior"""
    user_id: str
    created_at: datetime
    updated_at: datetime
    
    # Temporal patterns
    typical_hours: List[int]
    typical_days: List[int]
    business_hours_percentage: float
    
    # Geographic patterns
    typical_countries: List[str]
    typical_cities: List[str]
    geo_centroid: Tuple[float, float]
    geo_radius_95th: float
    
    # Device patterns
    typical_devices: List[str]
    typical_os: List[str]
    typical_browsers: List[str]
    
    # Application patterns
    typical_applications: List[str]
    application_frequency: Dict[str, float]
    
    # Statistical features
    login_frequency_mean: float
    login_frequency_std: float
    session_duration_mean: float
    session_duration_std: float
    
    # Anomaly detection models
    isolation_forest_model: Optional[Any] = None
    clustering_model: Optional[Any] = None
    
    # Baseline metadata
    sample_count: int = 0
    learning_period_days: int = 30
    confidence_score: float = 0.0


class BehaviorBaselineEngine:
    """
    Core engine for building and maintaining user behavior baselines
    """
    
    def __init__(self, config_path: str = None):
        """Initialize the baseline engine"""
        self.baselines: Dict[str, BehaviorBaseline] = {}
        self.scaler = StandardScaler()
        self.config = self._load_config(config_path)
        
        # Anomaly detection parameters
        self.contamination = 0.1  # Expected proportion of anomalies
        self.min_samples_for_baseline = 100
        self.learning_period_days = 30
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration settings"""
        default_config = {
            "min_events_for_baseline": 100,
            "learning_period_days": 30,
            "business_hours_start": 8,
            "business_hours_end": 18,
            "anomaly_threshold": 2.5,
            "update_frequency_hours": 24
        }
        
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except FileNotFoundError:
                logger.warning(f"Config file {config_path} not found, using defaults")
        
        return default_config
    
    def extract_features_from_event(self, event: Dict[str, Any]) -> BehaviorFeatures:
        """Extract behavior features from Okta event"""
        
        # Parse timestamp
        published = event.get("published", "")
        try:
            timestamp = datetime.fromisoformat(published.replace('Z', '+00:00'))
        except ValueError:
            timestamp = datetime.now()
        
        # Extract user information
        actor = event.get("actor", {})
        user_id = actor.get("alternateId", "unknown")
        
        # Extract client information
        client = event.get("client", {})
        geo_context = client.get("geographicalcontext", {})
        user_agent = client.get("useragent", {})
        
        # Temporal features
        hour_of_day = timestamp.hour
        day_of_week = timestamp.weekday()
        is_weekend = day_of_week >= 5
        is_business_hours = (
            self.config["business_hours_start"] <= hour_of_day < self.config["business_hours_end"]
            and not is_weekend
        )
        
        # Geographic features
        country = geo_context.get("country", "unknown")
        city = geo_context.get("city", "unknown")
        latitude = float(geo_context.get("geolocation", {}).get("lat", 0))
        longitude = float(geo_context.get("geolocation", {}).get("lon", 0))
        
        # Device/Network features
        device_type = user_agent.get("os", "unknown")
        os_type = user_agent.get("os", "unknown") 
        browser_type = user_agent.get("browser", "unknown")
        ip_address = client.get("ipaddress", "unknown")
        network_zone = client.get("zone", "unknown")
        
        # Application features
        target_info = event.get("target", [])
        app_name = "unknown"
        if isinstance(target_info, list) and target_info:
            for target in target_info:
                if target.get("type") == "AppInstance":
                    app_name = target.get("displayName", "unknown")
                    break
        
        # Authentication method
        auth_method = event.get("authenticationcontext", {}).get("authenticationstep", "unknown")
        
        # Session duration (placeholder - would need session correlation)
        session_duration = 0
        
        # Risk indicators (would be enhanced with historical data)
        is_new_device = self._is_new_device(user_id, device_type, user_agent)
        is_new_location = self._is_new_location(user_id, country, city)
        failed_attempts_recent = self._count_recent_failures(user_id)
        privilege_level = self._determine_privilege_level(actor)
        
        return BehaviorFeatures(
            user_id=user_id,
            timestamp=timestamp,
            hour_of_day=hour_of_day,
            day_of_week=day_of_week,
            is_weekend=is_weekend,
            is_business_hours=is_business_hours,
            country=country,
            city=city,
            latitude=latitude,
            longitude=longitude,
            device_type=device_type,
            os_type=os_type,
            browser_type=browser_type,
            ip_address=ip_address,
            network_zone=network_zone,
            application_name=app_name,
            authentication_method=auth_method,
            session_duration=session_duration,
            is_new_device=is_new_device,
            is_new_location=is_new_location,
            failed_attempts_recent=failed_attempts_recent,
            privilege_level=privilege_level
        )
    
    def build_baseline(self, user_id: str, features_history: List[BehaviorFeatures]) -> BehaviorBaseline:
        """Build behavior baseline for a user from historical features"""
        
        if len(features_history) < self.min_samples_for_baseline:
            logger.warning(f"Insufficient data for {user_id}: {len(features_history)} samples")
            return None
        
        # Convert features to DataFrame for analysis
        df = pd.DataFrame([asdict(f) for f in features_history])
        
        # Temporal analysis
        typical_hours = df['hour_of_day'].value_counts().head(8).index.tolist()
        typical_days = df['day_of_week'].value_counts().head(5).index.tolist()
        business_hours_percentage = df['is_business_hours'].mean()
        
        # Geographic analysis
        typical_countries = df['country'].value_counts().head(3).index.tolist()
        typical_cities = df['city'].value_counts().head(5).index.tolist()
        
        # Calculate geographic centroid and spread
        valid_coords = df[(df['latitude'] != 0) & (df['longitude'] != 0)]
        if len(valid_coords) > 0:
            geo_centroid = (
                valid_coords['latitude'].mean(),
                valid_coords['longitude'].mean()
            )
            # Calculate 95th percentile distance from centroid
            distances = self._calculate_distances(valid_coords, geo_centroid)
            geo_radius_95th = np.percentile(distances, 95)
        else:
            geo_centroid = (0.0, 0.0)
            geo_radius_95th = 0.0
        
        # Device pattern analysis
        typical_devices = df['device_type'].value_counts().head(5).index.tolist()
        typical_os = df['os_type'].value_counts().head(3).index.tolist()
        typical_browsers = df['browser_type'].value_counts().head(3).index.tolist()
        
        # Application pattern analysis
        app_counts = df['application_name'].value_counts()
        typical_applications = app_counts.head(10).index.tolist()
        total_app_accesses = len(df)
        application_frequency = {
            app: count / total_app_accesses 
            for app, count in app_counts.items()
        }
        
        # Statistical features
        login_times = df['timestamp'].dt.hour
        login_frequency_mean = len(df) / self.learning_period_days
        login_frequency_std = np.std([
            len(df[df['timestamp'].dt.date == date])
            for date in df['timestamp'].dt.date.unique()
        ])
        
        session_duration_mean = df['session_duration'].mean()
        session_duration_std = df['session_duration'].std()
        
        # Train anomaly detection models
        numerical_features = self._extract_numerical_features(df)
        
        # Isolation Forest for anomaly detection
        isolation_forest = IsolationForest(
            contamination=self.contamination,
            random_state=42
        )
        isolation_forest.fit(numerical_features)
        
        # DBSCAN for clustering normal behavior
        clustering = DBSCAN(eps=0.5, min_samples=5)
        clustering.fit(numerical_features)
        
        # Calculate confidence score based on data quality
        confidence_score = self._calculate_confidence_score(df, features_history)
        
        return BehaviorBaseline(
            user_id=user_id,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            typical_hours=typical_hours,
            typical_days=typical_days,
            business_hours_percentage=business_hours_percentage,
            typical_countries=typical_countries,
            typical_cities=typical_cities,
            geo_centroid=geo_centroid,
            geo_radius_95th=geo_radius_95th,
            typical_devices=typical_devices,
            typical_os=typical_os,
            typical_browsers=typical_browsers,
            typical_applications=typical_applications,
            application_frequency=application_frequency,
            login_frequency_mean=login_frequency_mean,
            login_frequency_std=login_frequency_std,
            session_duration_mean=session_duration_mean,
            session_duration_std=session_duration_std,
            isolation_forest_model=isolation_forest,
            clustering_model=clustering,
            sample_count=len(features_history),
            learning_period_days=self.learning_period_days,
            confidence_score=confidence_score
        )
    
    def update_baseline(self, user_id: str, new_features: List[BehaviorFeatures]) -> bool:
        """Update existing baseline with new features"""
        
        if user_id not in self.baselines:
            logger.warning(f"No existing baseline for {user_id}")
            return False
        
        baseline = self.baselines[user_id]
        
        # Incremental update logic
        # In production, this would use streaming algorithms
        logger.info(f"Updating baseline for {user_id} with {len(new_features)} new features")
        
        # Update timestamp
        baseline.updated_at = datetime.now()
        
        # Update sample count
        baseline.sample_count += len(new_features)
        
        # For simplicity, trigger full rebuild if significant new data
        # In production, use incremental algorithms
        if len(new_features) > baseline.sample_count * 0.1:
            logger.info(f"Significant new data for {user_id}, triggering full rebuild")
            return False  # Indicates full rebuild needed
        
        return True
    
    def calculate_anomaly_score(self, user_id: str, features: BehaviorFeatures) -> float:
        """Calculate anomaly score for given features against user baseline"""
        
        if user_id not in self.baselines:
            logger.warning(f"No baseline for {user_id}, cannot calculate anomaly score")
            return 0.5  # Neutral score
        
        baseline = self.baselines[user_id]
        
        # Calculate various anomaly components
        temporal_anomaly = self._calculate_temporal_anomaly(features, baseline)
        geographic_anomaly = self._calculate_geographic_anomaly(features, baseline)
        device_anomaly = self._calculate_device_anomaly(features, baseline)
        application_anomaly = self._calculate_application_anomaly(features, baseline)
        
        # Use ML model if available
        ml_anomaly = 0.5
        if baseline.isolation_forest_model:
            ml_anomaly = self._calculate_ml_anomaly_score(features, baseline)
        
        # Weighted combination of anomaly scores
        weights = {
            'temporal': 0.2,
            'geographic': 0.3,
            'device': 0.2,
            'application': 0.2,
            'ml_model': 0.1
        }
        
        combined_score = (
            weights['temporal'] * temporal_anomaly +
            weights['geographic'] * geographic_anomaly +
            weights['device'] * device_anomaly +
            weights['application'] * application_anomaly +
            weights['ml_model'] * ml_anomaly
        )
        
        return min(max(combined_score, 0.0), 1.0)
    
    def _calculate_temporal_anomaly(self, features: BehaviorFeatures, baseline: BehaviorBaseline) -> float:
        """Calculate temporal behavior anomaly score"""
        score = 0.0
        
        # Hour of day anomaly
        if features.hour_of_day not in baseline.typical_hours:
            score += 0.3
        
        # Day of week anomaly
        if features.day_of_week not in baseline.typical_days:
            score += 0.2
        
        # Business hours anomaly
        if features.is_business_hours != (baseline.business_hours_percentage > 0.5):
            score += 0.3
        
        # Weekend activity anomaly
        if features.is_weekend and baseline.business_hours_percentage > 0.8:
            score += 0.2
        
        return min(score, 1.0)
    
    def _calculate_geographic_anomaly(self, features: BehaviorFeatures, baseline: BehaviorBaseline) -> float:
        """Calculate geographic behavior anomaly score"""
        score = 0.0
        
        # Country anomaly
        if features.country not in baseline.typical_countries:
            score += 0.5
        
        # City anomaly
        if features.city not in baseline.typical_cities:
            score += 0.3
        
        # Distance from geographic centroid
        if baseline.geo_centroid != (0.0, 0.0):
            distance = self._calculate_distance(
                (features.latitude, features.longitude),
                baseline.geo_centroid
            )
            if distance > baseline.geo_radius_95th:
                score += 0.4
        
        return min(score, 1.0)
    
    def _calculate_device_anomaly(self, features: BehaviorFeatures, baseline: BehaviorBaseline) -> float:
        """Calculate device/technical anomaly score"""
        score = 0.0
        
        # Device type anomaly
        if features.device_type not in baseline.typical_devices:
            score += 0.4
        
        # OS anomaly
        if features.os_type not in baseline.typical_os:
            score += 0.3
        
        # Browser anomaly
        if features.browser_type not in baseline.typical_browsers:
            score += 0.3
        
        return min(score, 1.0)
    
    def _calculate_application_anomaly(self, features: BehaviorFeatures, baseline: BehaviorBaseline) -> float:
        """Calculate application access anomaly score"""
        score = 0.0
        
        # Application access anomaly
        if features.application_name not in baseline.typical_applications:
            score += 0.5
        elif features.application_name in baseline.application_frequency:
            # Check if access frequency is unusual
            expected_freq = baseline.application_frequency[features.application_name]
            if expected_freq < 0.1:  # Rarely accessed application
                score += 0.3
        
        return min(score, 1.0)
    
    def _calculate_ml_anomaly_score(self, features: BehaviorFeatures, baseline: BehaviorBaseline) -> float:
        """Calculate ML-based anomaly score"""
        try:
            # Convert features to numerical format
            feature_vector = self._features_to_vector(features)
            
            # Get anomaly score from Isolation Forest
            anomaly_score = baseline.isolation_forest_model.decision_function([feature_vector])[0]
            
            # Normalize to 0-1 range (Isolation Forest returns negative values for anomalies)
            normalized_score = max(0, -anomaly_score)
            
            return min(normalized_score, 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating ML anomaly score: {e}")
            return 0.5
    
    def _features_to_vector(self, features: BehaviorFeatures) -> List[float]:
        """Convert BehaviorFeatures to numerical vector for ML"""
        return [
            features.hour_of_day / 24.0,
            features.day_of_week / 7.0,
            1.0 if features.is_weekend else 0.0,
            1.0 if features.is_business_hours else 0.0,
            features.latitude / 90.0,
            features.longitude / 180.0,
            1.0 if features.is_new_device else 0.0,
            1.0 if features.is_new_location else 0.0,
            features.failed_attempts_recent / 10.0,
            features.session_duration / 3600.0  # Normalize to hours
        ]
    
    def _extract_numerical_features(self, df: pd.DataFrame) -> np.ndarray:
        """Extract numerical features for ML training"""
        features = []
        for _, row in df.iterrows():
            vector = [
                row['hour_of_day'] / 24.0,
                row['day_of_week'] / 7.0,
                1.0 if row['is_weekend'] else 0.0,
                1.0 if row['is_business_hours'] else 0.0,
                row['latitude'] / 90.0,
                row['longitude'] / 180.0,
                1.0 if row['is_new_device'] else 0.0,
                1.0 if row['is_new_location'] else 0.0,
                row['failed_attempts_recent'] / 10.0,
                row['session_duration'] / 3600.0
            ]
            features.append(vector)
        
        return np.array(features)
    
    def _calculate_distances(self, coords_df: pd.DataFrame, centroid: Tuple[float, float]) -> List[float]:
        """Calculate distances from centroid"""
        distances = []
        for _, row in coords_df.iterrows():
            distance = self._calculate_distance(
                (row['latitude'], row['longitude']),
                centroid
            )
            distances.append(distance)
        return distances
    
    def _calculate_distance(self, coord1: Tuple[float, float], coord2: Tuple[float, float]) -> float:
        """Calculate distance between two coordinates (simplified)"""
        # Haversine formula would be more accurate for geographic distances
        lat_diff = abs(coord1[0] - coord2[0])
        lon_diff = abs(coord1[1] - coord2[1])
        return np.sqrt(lat_diff**2 + lon_diff**2)
    
    def _calculate_confidence_score(self, df: pd.DataFrame, features_history: List[BehaviorFeatures]) -> float:
        """Calculate confidence score for baseline quality"""
        score = 0.0
        
        # Sample size factor
        sample_factor = min(len(features_history) / self.min_samples_for_baseline, 1.0)
        score += 0.3 * sample_factor
        
        # Time span factor
        if len(df) > 0:
            time_span = (df['timestamp'].max() - df['timestamp'].min()).days
            time_factor = min(time_span / self.learning_period_days, 1.0)
            score += 0.3 * time_factor
        
        # Data completeness factor
        complete_records = len(df[
            (df['latitude'] != 0) &
            (df['longitude'] != 0) &
            (df['device_type'] != 'unknown') &
            (df['application_name'] != 'unknown')
        ])
        completeness_factor = complete_records / len(df) if len(df) > 0 else 0
        score += 0.4 * completeness_factor
        
        return score
    
    def _is_new_device(self, user_id: str, device_type: str, user_agent: Dict[str, Any]) -> bool:
        """Check if this is a new device for the user (placeholder)"""
        # In production, this would check historical device data
        return False
    
    def _is_new_location(self, user_id: str, country: str, city: str) -> bool:
        """Check if this is a new location for the user (placeholder)"""
        # In production, this would check historical location data
        return False
    
    def _count_recent_failures(self, user_id: str) -> int:
        """Count recent authentication failures (placeholder)"""
        # In production, this would query recent failure events
        return 0
    
    def _determine_privilege_level(self, actor: Dict[str, Any]) -> str:
        """Determine user privilege level from actor data"""
        # Simple heuristic based on user ID patterns
        user_id = actor.get("alternateId", "").lower()
        
        if any(term in user_id for term in ['admin', 'root', 'superuser']):
            return "high"
        elif any(term in user_id for term in ['service', 'system', 'automation']):
            return "system"
        else:
            return "standard"
    
    def save_baseline(self, user_id: str, filepath: str):
        """Save baseline model to disk"""
        if user_id not in self.baselines:
            raise ValueError(f"No baseline found for user {user_id}")
        
        baseline = self.baselines[user_id]
        
        # Prepare data for serialization (exclude non-serializable models)
        baseline_dict = asdict(baseline)
        baseline_dict['isolation_forest_model'] = None
        baseline_dict['clustering_model'] = None
        
        # Save baseline metadata
        with open(f"{filepath}_baseline.json", 'w') as f:
            json.dump(baseline_dict, f, default=str, indent=2)
        
        # Save models separately
        if baseline.isolation_forest_model:
            joblib.dump(baseline.isolation_forest_model, f"{filepath}_isolation_forest.pkl")
        
        if baseline.clustering_model:
            joblib.dump(baseline.clustering_model, f"{filepath}_clustering.pkl")
    
    def load_baseline(self, user_id: str, filepath: str):
        """Load baseline model from disk"""
        
        # Load baseline metadata
        with open(f"{filepath}_baseline.json", 'r') as f:
            baseline_dict = json.load(f)
        
        # Convert timestamp strings back to datetime objects
        baseline_dict['created_at'] = datetime.fromisoformat(baseline_dict['created_at'])
        baseline_dict['updated_at'] = datetime.fromisoformat(baseline_dict['updated_at'])
        
        # Load models
        try:
            baseline_dict['isolation_forest_model'] = joblib.load(f"{filepath}_isolation_forest.pkl")
        except FileNotFoundError:
            baseline_dict['isolation_forest_model'] = None
        
        try:
            baseline_dict['clustering_model'] = joblib.load(f"{filepath}_clustering.pkl")
        except FileNotFoundError:
            baseline_dict['clustering_model'] = None
        
        # Create baseline object
        baseline = BehaviorBaseline(**baseline_dict)
        self.baselines[user_id] = baseline