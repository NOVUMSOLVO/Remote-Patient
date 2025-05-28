"""
Security Monitoring and Alerting System
Real-time security monitoring with NHS Digital compliance
"""

import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from flask import current_app, request
from app.models import SecurityAuditLog, User, db
from app.utils.security import AuditLogger
import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart


class AlertSeverity(Enum):
    """Security alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(Enum):
    """Types of security threats"""
    AUTHENTICATION_FAILURE = "auth_failure"
    BRUTE_FORCE = "brute_force"
    SUSPICIOUS_ACCESS = "suspicious_access"
    DATA_BREACH_ATTEMPT = "data_breach"
    DDoS_ATTACK = "ddos_attack"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE_DETECTION = "malware"
    SQL_INJECTION = "sql_injection"
    XSS_ATTEMPT = "xss_attempt"
    NHS_COMPLIANCE_VIOLATION = "nhs_violation"


@dataclass
class SecurityAlert:
    """Security alert data structure"""
    alert_id: str
    timestamp: datetime
    severity: AlertSeverity
    threat_type: ThreatType
    source_ip: str
    user_id: Optional[int]
    description: str
    details: Dict[str, Any]
    resolved: bool = False
    resolved_by: Optional[int] = None
    resolved_at: Optional[datetime] = None


class SecurityMonitor:
    """Real-time security monitoring system"""
    
    def __init__(self):
        self.alerts = []
        self.audit_logger = AuditLogger()
        self.active_threats = {}
        self.monitoring_rules = self._load_monitoring_rules()
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
    
    def _load_monitoring_rules(self) -> Dict[str, Any]:
        """Load security monitoring rules"""
        return {
            'failed_login_threshold': 5,
            'failed_login_window': 300,  # 5 minutes
            'suspicious_ip_threshold': 10,
            'data_access_rate_limit': 100,  # requests per minute
            'unusual_hour_threshold': 22,  # 10 PM
            'max_session_duration': 480,  # 8 hours
            'geo_anomaly_threshold': 1000,  # km
            'privilege_escalation_keywords': [
                'admin', 'root', 'sudo', 'grant', 'alter'
            ],
            'data_exfiltration_threshold': 1000,  # records
            'nhs_data_access_monitoring': True
        }
    
    def monitor_authentication(self, user_id: int, ip_address: str, 
                             success: bool, user_agent: Optional[str] = None) -> None:
        """Monitor authentication events"""
        try:
            # Log authentication attempt
            self.audit_logger.log_security_event(
                event_type='authentication',
                user_id=user_id if success else 0,
                description=f"Authentication {'successful' if success else 'failed'} from {ip_address}",
                severity='info' if success else 'warning'
            )
            
            if not success:
                self._check_brute_force_attack(user_id, ip_address)
                self._check_suspicious_access_patterns(ip_address)
            else:
                self._check_unusual_access_time(user_id)
                self._check_geographic_anomaly(user_id, ip_address)
                
        except Exception as e:
            self.logger.error(f"Authentication monitoring error: {str(e)}")
    
    def monitor_data_access(self, user_id: int, resource: str, 
                           action: str, ip_address: str) -> None:
        """Monitor data access patterns"""
        try:
            # Log data access
            self.audit_logger.log_security_event(
                event_type='data_access',
                user_id=user_id,
                description=f"Data access: {action} on {resource} from {ip_address}",
                severity='info'
            )
            
            # Check for suspicious patterns
            self._check_data_access_rate(user_id, ip_address)
            self._check_privilege_escalation(user_id, action, resource)
            
            # NHS-specific monitoring
            if 'patient' in resource.lower() or 'nhs' in resource.lower():
                self._check_nhs_data_access(user_id, resource, action)
                
        except Exception as e:
            self.logger.error(f"Data access monitoring error: {str(e)}")
    
    def monitor_system_activity(self, activity_type: str, details: Dict[str, Any]) -> None:
        """Monitor system-level activities"""
        try:
            # Check for DDoS patterns
            if activity_type == 'request':
                ip_address = details.get('ip_address')
                if ip_address:
                    self._check_ddos_patterns(ip_address)
            
            # Check for malware indicators
            if activity_type == 'file_upload':
                self._check_malware_indicators(details)
            
            # Check for SQL injection attempts
            if activity_type == 'database_query':
                self._check_sql_injection(details)
                
        except Exception as e:
            self.logger.error(f"System activity monitoring error: {str(e)}")
    
    def _check_brute_force_attack(self, user_id: int, ip_address: str) -> None:
        """Check for brute force attack patterns"""
        window_start = datetime.utcnow() - timedelta(
            seconds=self.monitoring_rules['failed_login_window']
        )
        
        # Count failed attempts in window
        failed_attempts = db.session.query(SecurityAuditLog).filter(
            SecurityAuditLog.event_type == 'authentication',
            SecurityAuditLog.ip_address == ip_address,
            SecurityAuditLog.success == False,
            SecurityAuditLog.timestamp >= window_start
        ).count()
        
        if failed_attempts >= self.monitoring_rules['failed_login_threshold']:
            self._create_alert(
                severity=AlertSeverity.HIGH,
                threat_type=ThreatType.BRUTE_FORCE,
                source_ip=ip_address,
                user_id=user_id,
                description=f"Brute force attack detected: {failed_attempts} failed attempts",
                details={
                    'failed_attempts': failed_attempts,
                    'window_minutes': self.monitoring_rules['failed_login_window'] // 60
                }
            )
    
    def _check_suspicious_access_patterns(self, ip_address: str) -> None:
        """Check for suspicious access patterns"""
        # Check if IP is accessing multiple accounts
        window_start = datetime.utcnow() - timedelta(hours=1)
        
        unique_users = db.session.query(SecurityAuditLog.user_id).filter(
            SecurityAuditLog.ip_address == ip_address,
            SecurityAuditLog.timestamp >= window_start,
            SecurityAuditLog.user_id.isnot(None)
        ).distinct().count()
        
        if unique_users >= self.monitoring_rules['suspicious_ip_threshold']:
            self._create_alert(
                severity=AlertSeverity.MEDIUM,
                threat_type=ThreatType.SUSPICIOUS_ACCESS,
                source_ip=ip_address,
                description=f"Suspicious IP accessing {unique_users} different accounts",
                details={'unique_users_accessed': unique_users}
            )
    
    def _check_unusual_access_time(self, user_id: int) -> None:
        """Check for access during unusual hours"""
        current_hour = datetime.utcnow().hour
        
        if current_hour >= self.monitoring_rules['unusual_hour_threshold'] or current_hour <= 5:
            # Check if this is unusual for this user
            user = User.query.get(user_id)
            if user:
                self._create_alert(
                    severity=AlertSeverity.LOW,
                    threat_type=ThreatType.SUSPICIOUS_ACCESS,
                    source_ip=request.remote_addr if request else 'unknown',
                    user_id=user_id,
                    description=f"Access during unusual hours: {current_hour}:00",
                    details={'access_hour': current_hour}
                )
    
    def _check_geographic_anomaly(self, user_id: int, ip_address: str) -> None:
        """Check for geographic access anomalies"""
        # This would integrate with IP geolocation service
        # For now, we'll implement a basic check
        
        # Get user's recent access locations
        recent_locations = self._get_recent_access_locations(user_id)
        current_location = self._get_ip_location(ip_address)
        
        if recent_locations and current_location:
            # Calculate distance (simplified)
            distance = self._calculate_distance(recent_locations[-1], current_location)
            
            if distance > self.monitoring_rules['geo_anomaly_threshold']:
                self._create_alert(
                    severity=AlertSeverity.MEDIUM,
                    threat_type=ThreatType.SUSPICIOUS_ACCESS,
                    source_ip=ip_address,
                    user_id=user_id,
                    description=f"Geographic anomaly: {distance}km from usual location",
                    details={
                        'distance_km': distance,
                        'current_location': current_location,
                        'previous_location': recent_locations[-1]
                    }
                )
    
    def _check_data_access_rate(self, user_id: int, ip_address: str) -> None:
        """Check for unusual data access rates"""
        window_start = datetime.utcnow() - timedelta(minutes=1)
        
        access_count = db.session.query(SecurityAuditLog).filter(
            SecurityAuditLog.event_type == 'data_access',
            SecurityAuditLog.user_id == user_id,
            SecurityAuditLog.timestamp >= window_start
        ).count()
        
        if access_count >= self.monitoring_rules['data_access_rate_limit']:
            self._create_alert(
                severity=AlertSeverity.HIGH,
                threat_type=ThreatType.DATA_EXFILTRATION,
                source_ip=ip_address,
                user_id=user_id,
                description=f"Unusual data access rate: {access_count} requests/minute",
                details={'access_count': access_count}
            )
    
    def _check_privilege_escalation(self, user_id: int, action: str, resource: str) -> None:
        """Check for privilege escalation attempts"""
        keywords = self.monitoring_rules['privilege_escalation_keywords']
        
        if any(keyword in action.lower() or keyword in resource.lower() for keyword in keywords):
            user = User.query.get(user_id)
            if user and user.role not in ['admin', 'super_admin']:
                self._create_alert(
                    severity=AlertSeverity.HIGH,
                    threat_type=ThreatType.PRIVILEGE_ESCALATION,
                    source_ip=request.remote_addr if request else 'unknown',
                    user_id=user_id,
                    description=f"Privilege escalation attempt: {action} on {resource}",
                    details={
                        'action': action,
                        'resource': resource,
                        'user_role': user.role
                    }
                )
    
    def _check_nhs_data_access(self, user_id: int, resource: str, action: str) -> None:
        """Check NHS-specific data access compliance"""
        if not self.monitoring_rules['nhs_data_access_monitoring']:
            return
        
        # Check if user has proper NHS credentials
        user = User.query.get(user_id)
        if user and not getattr(user, 'nhs_verified', False):
            self._create_alert(
                severity=AlertSeverity.CRITICAL,
                threat_type=ThreatType.NHS_COMPLIANCE_VIOLATION,
                source_ip=request.remote_addr if request else 'unknown',
                user_id=user_id,
                description=f"NHS data access by unverified user: {action} on {resource}",
                details={
                    'resource': resource,
                    'action': action,
                    'nhs_verified': False
                }
            )
    
    def _check_ddos_patterns(self, ip_address: str) -> None:
        """Check for DDoS attack patterns"""
        window_start = datetime.utcnow() - timedelta(minutes=1)
        
        request_count = db.session.query(SecurityAuditLog).filter(
            SecurityAuditLog.ip_address == ip_address,
            SecurityAuditLog.timestamp >= window_start
        ).count()
        
        if request_count >= 100:  # Threshold for DDoS
            self._create_alert(
                severity=AlertSeverity.CRITICAL,
                threat_type=ThreatType.DDoS_ATTACK,
                source_ip=ip_address,
                description=f"Potential DDoS attack: {request_count} requests/minute",
                details={'request_count': request_count}
            )
    
    def _check_malware_indicators(self, details: Dict[str, Any]) -> None:
        """Check for malware indicators in file uploads"""
        filename = details.get('filename', '')
        file_content = details.get('content', '')
        
        # Simple malware indicators
        malware_patterns = [
            b'<script>',
            b'eval(',
            b'exec(',
            b'system(',
            b'shell_exec'
        ]
        
        if isinstance(file_content, bytes):
            for pattern in malware_patterns:
                if pattern in file_content:
                    self._create_alert(
                        severity=AlertSeverity.CRITICAL,
                        threat_type=ThreatType.MALWARE_DETECTION,
                        source_ip=request.remote_addr if request else 'unknown',
                        description=f"Malware detected in file upload: {filename}",
                        details={
                            'filename': filename,
                            'pattern_detected': pattern.decode('utf-8', errors='ignore')
                        }
                    )
                    break
    
    def _check_sql_injection(self, details: Dict[str, Any]) -> None:
        """Check for SQL injection attempts"""
        query = details.get('query', '')
        
        sql_injection_patterns = [
            "' OR '1'='1",
            "'; DROP TABLE",
            "UNION SELECT",
            "' OR 1=1",
            "'; INSERT INTO",
            "'; UPDATE",
            "'; DELETE FROM"
        ]
        
        for pattern in sql_injection_patterns:
            if pattern.lower() in query.lower():
                self._create_alert(
                    severity=AlertSeverity.HIGH,
                    threat_type=ThreatType.SQL_INJECTION,
                    source_ip=request.remote_addr if request else 'unknown',
                    description=f"SQL injection attempt detected",
                    details={
                        'query': query[:500],  # Limit query length
                        'pattern': pattern
                    }
                )
                break
    
    def _create_alert(self, severity: AlertSeverity, threat_type: ThreatType,
                     source_ip: str, description: str, details: Dict[str, Any],
                     user_id: Optional[int] = None) -> SecurityAlert:
        """Create and process security alert"""
        alert = SecurityAlert(
            alert_id=self._generate_alert_id(),
            timestamp=datetime.utcnow(),
            severity=severity,
            threat_type=threat_type,
            source_ip=source_ip,
            user_id=user_id,
            description=description,
            details=details
        )
        
        # Store alert
        self.alerts.append(alert)
        
        # Log to database
        self.audit_logger.log_security_event(
            event_type='security_alert',
            user_id=user_id or 0,
            description=f"Security alert: {threat_type.value} - {description}",
            severity='critical' if severity == AlertSeverity.CRITICAL else 'error'
        )
        
        # Send notifications based on severity
        if severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            self._send_alert_notification(alert)
        
        return alert
    
    def _generate_alert_id(self) -> str:
        """Generate unique alert ID"""
        timestamp = int(time.time() * 1000)
        return f"ALERT_{timestamp}"
    
    def _send_alert_notification(self, alert: SecurityAlert) -> None:
        """Send alert notification to security team"""
        try:
            if current_app.config.get('SECURITY_ALERTS_EMAIL_ENABLED', False):
                self._send_email_alert(alert)
            
            if current_app.config.get('SECURITY_ALERTS_SLACK_ENABLED', False):
                self._send_slack_alert(alert)
                
        except Exception as e:
            self.logger.error(f"Alert notification error: {str(e)}")
    
    def _send_email_alert(self, alert: SecurityAlert) -> None:
        """Send email alert"""
        smtp_config = current_app.config.get('SMTP_CONFIG', {})
        security_email = current_app.config.get('SECURITY_TEAM_EMAIL')
        
        if not smtp_config or not security_email:
            return
        
        msg = MimeMultipart()
        msg['From'] = smtp_config.get('from_email')
        msg['To'] = security_email
        msg['Subject'] = f"SECURITY ALERT [{alert.severity.value.upper()}] - {alert.threat_type.value}"
        
        body = f"""
        Security Alert Detected
        
        Alert ID: {alert.alert_id}
        Severity: {alert.severity.value.upper()}
        Threat Type: {alert.threat_type.value}
        Timestamp: {alert.timestamp}
        Source IP: {alert.source_ip}
        User ID: {alert.user_id or 'N/A'}
        
        Description: {alert.description}
        
        Details:
        {json.dumps(alert.details, indent=2)}
        
        Please investigate immediately.
        
        NHS Remote Patient Monitoring Security System
        """
        
        msg.attach(MimeText(body, 'plain'))
        
        server = smtplib.SMTP(smtp_config.get('host'), smtp_config.get('port'))
        server.starttls()
        server.login(smtp_config.get('username'), smtp_config.get('password'))
        server.send_message(msg)
        server.quit()
    
    def _send_slack_alert(self, alert: SecurityAlert) -> None:
        """Send Slack alert"""
        # Implementation would depend on Slack webhook configuration
        pass
    
    def _get_recent_access_locations(self, user_id: int) -> List[Dict[str, Any]]:
        """Get recent access locations for user"""
        # Simplified implementation
        return []
    
    def _get_ip_location(self, ip_address: str) -> Dict[str, Any]:
        """Get location from IP address"""
        # This would integrate with IP geolocation service
        return {}
    
    def _calculate_distance(self, loc1: Dict[str, Any], loc2: Dict[str, Any]) -> float:
        """Calculate distance between two locations"""
        # Simplified distance calculation
        return 0.0
    
    def get_active_alerts(self) -> List[SecurityAlert]:
        """Get all active (unresolved) alerts"""
        return [alert for alert in self.alerts if not alert.resolved]
    
    def resolve_alert(self, alert_id: str, resolved_by: int) -> bool:
        """Resolve a security alert"""
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.resolved = True
                alert.resolved_by = resolved_by
                alert.resolved_at = datetime.utcnow()
                
                # Log resolution
                self.audit_logger.log_security_event(
                    event_type='alert_resolved',
                    user_id=resolved_by,
                    description=f"Security alert {alert_id} resolved",
                    severity='info'
                )
                return True
        return False
    
    def get_threat_intelligence(self) -> Dict[str, Any]:
        """Get threat intelligence summary"""
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        
        # Count alerts by type in last 24 hours
        threat_counts = {}
        for alert in self.alerts:
            if alert.timestamp >= last_24h:
                threat_type = alert.threat_type.value
                threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
        # Top threat sources
        source_counts = {}
        for alert in self.alerts:
            if alert.timestamp >= last_24h:
                source_counts[alert.source_ip] = source_counts.get(alert.source_ip, 0) + 1
        
        top_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'total_alerts_24h': len([a for a in self.alerts if a.timestamp >= last_24h]),
            'threat_types': threat_counts,
            'top_threat_sources': top_sources,
            'critical_alerts': len([a for a in self.alerts 
                                  if a.timestamp >= last_24h and a.severity == AlertSeverity.CRITICAL]),
            'unresolved_alerts': len(self.get_active_alerts())
        }


# Global security monitor instance
security_monitor = SecurityMonitor()
