#!/usr/bin/env python3
"""
CIVOPS-Radar: Risk Assessment Engine
Author: CIVOPS-Radar Contributors
License: MIT

Advanced risk scoring algorithm for Wi-Fi network analysis.
Evaluates security posture and potential threats based on network characteristics.
"""

import re
import math
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

try:
    from flock_detector import detector as flock_detector
except ImportError:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from flock_detector import detector as flock_detector

@dataclass
class NetworkProfile:
    """Network profile for risk assessment"""
    bssid: str
    ssid: str
    capabilities: str
    frequency: int
    level: int
    is_hidden: bool
    is_open: bool
    vendor: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    scan_count: int = 1

@dataclass
class RiskFactors:
    """Individual risk factors and their scores"""
    open_network: int = 0
    hidden_ssid: int = 0
    weak_encryption: int = 0
    suspicious_ssid: int = 0
    signal_fluctuation: int = 0
    proximity_risk: int = 0
    vendor_risk: int = 0
    beacon_anomaly: int = 0
    channel_conflict: int = 0
    temporal_risk: int = 0
    surveillance_risk: int = 0

class RiskEngine:
    """Advanced risk assessment engine for Wi-Fi networks"""
    
    def __init__(self):
        self.suspicious_patterns = [
            r'(?i)(free|public|guest|open)',
            r'(?i)(wifi|internet|hotspot)',
            r'(?i)(admin|root|test|demo)',
            r'(?i)(hack|crack|pwn)',
            r'(?i)(evil|rogue|fake)',
            r'(?i)(airport|hotel|coffee)',
            r'(?i)(mobile|phone|android)',
            r'(?i)(backdoor|trojan|virus)'
        ]
        
        self.risky_vendors = [
            'Cisco', 'Linksys', 'Netgear', 'D-Link', 'TP-Link',
            'Belkin', 'ASUS', 'Ubiquiti', 'Mikrotik'
        ]
        
        self.encryption_strength = {
            'WEP': 0,      # Very weak
            'WPA': 20,     # Weak
            'WPA2': 40,    # Moderate
            'WPA3': 60,    # Strong
            'WPA2-PSK': 30, # Moderate
            'WPA3-SAE': 70  # Very strong
        }
    
    def calculate_risk_score(self, network: NetworkProfile, 
                     historical_data: List[NetworkProfile] = None) -> Tuple[int, RiskFactors]:
        """
        Calculate comprehensive risk score for a network
        
        Args:
            network: Current network profile
            historical_data: Historical scan data for trend analysis
            
        Returns:
            Tuple of (total_risk_score, risk_factors)
        """
        factors = RiskFactors()
        
        # Basic security assessment
        factors.open_network = self._assess_open_network(network)
        factors.hidden_ssid = self._assess_hidden_ssid(network)
        factors.weak_encryption = self._assess_encryption_strength(network)
        factors.suspicious_ssid = self._assess_suspicious_ssid(network)
        
        # Surveillance & ALPR assessment
        flock_res = flock_detector.analyze(
            bssid=network.bssid,
            ssid=network.ssid,
            capabilities=network.capabilities,
            level=network.level,
            frequency=network.frequency
        )
        if flock_res.is_flock:
            factors.surveillance_risk = 60 if flock_res.confidence == "CONFIRMED" else 50
        elif flock_res.is_alpr:
            factors.surveillance_risk = 40
        
        # Advanced threat detection
        if historical_data:
            factors.signal_fluctuation = self._assess_signal_fluctuation(network, historical_data)
            factors.temporal_risk = self._assess_temporal_patterns(network, historical_data)
        
        factors.proximity_risk = self._assess_proximity_risk(network)
        factors.vendor_risk = self._assess_vendor_risk(network)
        factors.beacon_anomaly = self._assess_beacon_anomalies(network)
        factors.channel_conflict = self._assess_channel_conflicts(network)
        
        # Calculate total risk score (0-100)
        total_score = min(100, max(0, sum([
            factors.open_network,
            factors.hidden_ssid,
            factors.weak_encryption,
            factors.suspicious_ssid,
            factors.signal_fluctuation,
            factors.proximity_risk,
            factors.vendor_risk,
            factors.beacon_anomaly,
            factors.channel_conflict,
            factors.temporal_risk,
            factors.surveillance_risk
        ])))
        
        return total_score, factors
    
    def _assess_open_network(self, network: NetworkProfile) -> int:
        """Assess risk of open networks"""
        if network.is_open:
            return 30  # High risk for open networks
        return 0
    
    def _assess_hidden_ssid(self, network: NetworkProfile) -> int:
        """Assess risk of hidden SSIDs"""
        if network.is_hidden:
            return 20  # Medium risk for hidden networks
        return 0
    
    def _assess_encryption_strength(self, network: NetworkProfile) -> int:
        """Assess encryption strength"""
        if network.is_open:
            return 0  # Already counted in open_network
        
        capabilities = (network.capabilities or "").upper()
        
        # Check for weak encryption
        if 'WEP' in capabilities:
            return 25  # Very high risk
        elif 'WPA3' in capabilities or 'SAE' in capabilities:
            return 0   # No additional risk (WPA3 / SAE)
        elif 'WPA2' in capabilities or 'RSN' in capabilities:
            return 5   # Low risk (WPA2)
        elif 'WPA' in capabilities:
            return 15  # High risk (WPA1 legacy)
        else:
            return 20  # Unknown encryption
    
    def _assess_suspicious_ssid(self, network: NetworkProfile) -> int:
        """Assess SSID for suspicious patterns"""
        if not network.ssid:
            return 0
        
        ssid = network.ssid.lower()
        risk_score = 0
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, ssid):
                risk_score += 10
        
        return min(30, risk_score)  # Cap at 30 points
    
    def _assess_signal_fluctuation(self, network: NetworkProfile, 
                                 historical_data: List[NetworkProfile]) -> int:
        """Assess signal strength fluctuation patterns"""
        if len(historical_data) < 3:
            return 0
        
        # Get signal levels from historical data
        signal_levels = [n.level for n in historical_data if n.bssid == network.bssid]
        
        if len(signal_levels) < 3:
            return 0
        
        # Calculate standard deviation
        mean_level = sum(signal_levels) / len(signal_levels)
        variance = sum((x - mean_level) ** 2 for x in signal_levels) / len(signal_levels)
        std_dev = math.sqrt(variance)
        
        # High fluctuation indicates potential rogue AP
        if std_dev > 15:  # High fluctuation
            return 15
        elif std_dev > 10:  # Medium fluctuation
            return 8
        else:
            return 0
    
    def _assess_proximity_risk(self, network: NetworkProfile) -> int:
        """Assess proximity-based risks"""
        if not network.level:
            return 0
            
        risk_score = 0
        
        # Very strong signal (potential close proximity rogue AP)
        if network.level > -30:
            risk_score += 10
        elif network.level > -50:
            risk_score += 5
        
        # Very weak signal (potential distant threat)
        if network.level < -80:
            risk_score += 5
        
        return risk_score
    
    def _assess_vendor_risk(self, network: NetworkProfile) -> int:
        """Assess vendor-based risks"""
        if not network.vendor:
            return 0
        
        # Some vendors are more commonly targeted
        if network.vendor in self.risky_vendors:
            return 5
        
        return 0
    
    def _assess_beacon_anomalies(self, network: NetworkProfile) -> int:
        """Assess beacon frame anomalies"""
        risk_score = 0
        freq = network.frequency
        
        if not freq or freq == 0:
            return 10
        
        # Standard Wi-Fi bands:
        # 2.4 GHz (2400-2500 MHz), 5 GHz (5150-5900 MHz), 6 GHz (5925-7125 MHz)
        is_2ghz = (2400 <= freq <= 2500)
        is_5ghz = (5150 <= freq <= 5900)
        is_6ghz = (5925 <= freq <= 7125)
        
        if not (is_2ghz or is_5ghz or is_6ghz):
            risk_score += 25  # Frequency outside standard Wi-Fi bands
        elif is_2ghz and freq not in [2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467, 2472, 2484]:
            risk_score += 10  # Non-standard 2.4GHz channel
        
        return risk_score
    
    def _assess_channel_conflicts(self, network: NetworkProfile) -> int:
        """Assess channel conflict risks"""
        # This would require knowledge of other networks on same channel
        # For now, return 0 as we don't have that context
        return 0
    
    def _assess_temporal_patterns(self, network: NetworkProfile, 
                                historical_data: List[NetworkProfile]) -> int:
        """Assess temporal access patterns"""
        if not historical_data:
            return 0
        
        # Check for unusual access times
        current_hour = datetime.now().hour
        
        # Networks active during unusual hours (2-6 AM) might be suspicious
        if 2 <= current_hour <= 6:
            return 5
        
        return 0
    
    def get_risk_level(self, score: int) -> str:
        """Convert numeric score to risk level"""
        if score >= 70:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        elif score >= 10:
            return "LOW"
        else:
            return "MINIMAL"
    
    def get_risk_color(self, score: int) -> str:
        """Get color code for risk level"""
        if score >= 70:
            return "#ef4444"  # Red
        elif score >= 50:
            return "#f59e0b"  # Orange
        elif score >= 30:
            return "#eab308"  # Yellow
        elif score >= 10:
            return "#10b981"  # Green
        else:
            return "#6b7280"  # Gray
    
    def generate_risk_report(self, network: NetworkProfile, 
                           risk_score: int, factors: RiskFactors) -> Dict:
        """Generate detailed risk report"""
        flock_res = flock_detector.analyze(
            bssid=network.bssid,
            ssid=network.ssid,
            capabilities=network.capabilities,
            level=network.level,
            frequency=network.frequency
        )
        return {
            'bssid': network.bssid,
            'ssid': network.ssid,
            'risk_score': risk_score,
            'risk_level': self.get_risk_level(risk_score),
            'risk_color': self.get_risk_color(risk_score),
            'factors': {
                'open_network': factors.open_network,
                'hidden_ssid': factors.hidden_ssid,
                'weak_encryption': factors.weak_encryption,
                'suspicious_ssid': factors.suspicious_ssid,
                'signal_fluctuation': factors.signal_fluctuation,
                'proximity_risk': factors.proximity_risk,
                'vendor_risk': factors.vendor_risk,
                'beacon_anomaly': factors.beacon_anomaly,
                'channel_conflict': factors.channel_conflict,
                'temporal_risk': factors.temporal_risk,
                'surveillance_risk': factors.surveillance_risk
            },
            'flock_detection': {
                'is_flock': flock_res.is_flock,
                'is_alpr': flock_res.is_alpr,
                'confidence': flock_res.confidence,
                'confidence_score': flock_res.confidence_score,
                'device_type': flock_res.device_type,
                'vendor': flock_res.vendor,
                'reasons': flock_res.reasons
            },
            'recommendations': self._generate_recommendations(factors),
            'timestamp': datetime.now().isoformat()
        }
    
    def _generate_recommendations(self, factors: RiskFactors) -> List[str]:
        """Generate security recommendations based on risk factors"""
        recommendations = []
        
        if factors.surveillance_risk > 0:
            recommendations.append("🚨 SURVEILLANCE ALERT: Detected nearby Flock Safety ALPR / surveillance camera")
            recommendations.append("License plate reader active within RF perimeter")
        
        if factors.open_network > 0:
            recommendations.append("Avoid connecting to open networks")
        
        if factors.hidden_ssid > 0:
            recommendations.append("Be cautious of hidden networks")
        
        if factors.weak_encryption > 0:
            recommendations.append("Network uses weak encryption")
        
        if factors.suspicious_ssid > 0:
            recommendations.append("SSID appears suspicious")
        
        if factors.signal_fluctuation > 0:
            recommendations.append("Signal strength is unstable")
        
        if factors.proximity_risk > 0:
            recommendations.append("Network is very close or very far")
        
        if factors.vendor_risk > 0:
            recommendations.append("Vendor has known security issues")
        
        if factors.beacon_anomaly > 0:
            recommendations.append("Network uses unusual frequencies")
        
        if factors.temporal_risk > 0:
            recommendations.append("Network active during unusual hours")
        
        return recommendations

# Example usage and testing
if __name__ == "__main__":
    # Test the risk engine
    engine = RiskEngine()
    
    # Test network profiles
    test_networks = [
        NetworkProfile(
            bssid="00:11:22:33:44:55",
            ssid="HomeNetwork",
            capabilities="[WPA2-PSK-CCMP][ESS]",
            frequency=2412,
            level=-45,
            is_hidden=False,
            is_open=False
        ),
        NetworkProfile(
            bssid="00:11:22:33:44:56",
            ssid="FreeWiFi",
            capabilities="[ESS]",
            frequency=2437,
            level=-60,
            is_hidden=False,
            is_open=True
        ),
        NetworkProfile(
            bssid="00:11:22:33:44:57",
            ssid="",
            capabilities="[WPA2-PSK-CCMP][ESS]",
            frequency=2462,
            level=-70,
            is_hidden=True,
            is_open=False
        )
    ]
    
    for network in test_networks:
        score, factors = engine.calculate_risk_score(network)
        report = engine.generate_risk_report(network, score, factors)
        
        print(f"\nNetwork: {network.ssid or 'Hidden'}")
        print(f"Risk Score: {score}/100 ({engine.get_risk_level(score)})")
        print(f"Recommendations: {', '.join(report['recommendations'])}")
