"""
DDoS Protection and Advanced Security Middleware
Implements comprehensive protection against various attack vectors
"""

import time
import ipaddress
from collections import defaultdict, deque
from datetime import datetime, timedelta
from flask import request, jsonify, current_app, g
from functools import wraps
import redis
import logging
import re
import hashlib

logger = logging.getLogger(__name__)

class DDoSProtection:
    """Advanced DDoS protection with multiple detection strategies"""
    
    def __init__(self):
        self.redis_client = None
        self.connection_counts = defaultdict(lambda: deque())
        self.request_patterns = defaultdict(list)
        self.blocked_ips = set()
        self.suspicious_ips = defaultdict(int)
        
        # Initialize Redis if available
        try:
            redis_url = current_app.config.get('REDIS_URL', 'redis://localhost:6379/0')
            self.redis_client = redis.from_url(redis_url)
            self.redis_client.ping()
            logger.info("Redis connected for DDoS protection")
        except Exception as e:
            logger.warning(f"Redis not available, using in-memory storage: {str(e)}")
    
    def check_request_flood(self, ip_address: str) -> tuple[bool, str]:
        """Check for request flooding from IP"""
        current_time = time.time()
        window_size = 60  # 1 minute window
        max_requests = current_app.config.get('DDOS_MAX_REQUESTS_PER_MINUTE', 100)
        
        if self.redis_client:
            key = f"ddos:flood:{ip_address}"
            pipe = self.redis_client.pipeline()
            pipe.incr(key)
            pipe.expire(key, window_size)
            results = pipe.execute()
            request_count = results[0]
        else:
            # In-memory fallback
            if ip_address not in self.connection_counts:
                self.connection_counts[ip_address] = deque()
            
            # Clean old entries
            while (self.connection_counts[ip_address] and 
                   current_time - self.connection_counts[ip_address][0] > window_size):
                self.connection_counts[ip_address].popleft()
            
            self.connection_counts[ip_address].append(current_time)
            request_count = len(self.connection_counts[ip_address])
        
        if request_count > max_requests:
            self._block_ip(ip_address, "Request flooding", 300)  # 5 minute block
            return False, f"Request flooding detected: {request_count} requests/minute"
        
        return True, ""
    
    def check_pattern_analysis(self, ip_address: str, user_agent: str, path: str) -> tuple[bool, str]:
        """Analyze request patterns for bot-like behavior"""
        current_time = time.time()
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'/\.env',
            r'/wp-admin',
            r'/admin\.php',
            r'/phpmyadmin',
            r'/\.git',
            r'/config\.php',
            r'sqlmap',
            r'nikto',
            r'nmap'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                self.suspicious_ips[ip_address] += 10
                if self.suspicious_ips[ip_address] > 50:
                    self._block_ip(ip_address, f"Suspicious path access: {path}", 1800)  # 30 minute block
                    return False, f"Suspicious path access detected: {path}"
        
        # Check for bot-like user agents
        bot_patterns = [
            r'bot',
            r'crawler',
            r'spider',
            r'scraper',
            r'curl',
            r'wget',
            r'python-requests'
        ]
        
        for pattern in bot_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                # Allow legitimate bots but rate limit them more strictly
                if not self._is_legitimate_bot(user_agent):
                    self.suspicious_ips[ip_address] += 5
                    if self.suspicious_ips[ip_address] > 30:
                        self._block_ip(ip_address, f"Suspicious bot behavior: {user_agent}", 600)  # 10 minute block
                        return False, f"Suspicious bot behavior detected"
        
        return True, ""
    
    def check_geographic_anomalies(self, ip_address: str) -> tuple[bool, str]:
        """Check for geographic anomalies (basic implementation)"""
        # This would integrate with a GeoIP service in production
        # For now, implement basic checks
        
        # Block known malicious IP ranges (example)
        malicious_ranges = [
            '10.0.0.0/8',    # Private networks shouldn't access public APIs
            '172.16.0.0/12',
            '192.168.0.0/16'
        ]
        
        try:
            ip = ipaddress.ip_address(ip_address)
            for range_str in malicious_ranges:
                if ip in ipaddress.ip_network(range_str):
                    # Allow private networks in development
                    if current_app.config.get('ENVIRONMENT') == 'development':
                        return True, ""
                    
                    self._block_ip(ip_address, f"Private IP range access: {ip_address}", 3600)
                    return False, f"Access from private IP range not allowed: {ip_address}"
        except ValueError:
            # Invalid IP address
            self._block_ip(ip_address, f"Invalid IP address: {ip_address}", 3600)
            return False, f"Invalid IP address: {ip_address}"
        
        return True, ""
    
    def check_request_size(self, content_length: int) -> tuple[bool, str]:
        """Check for unusually large requests"""
        max_size = current_app.config.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024)  # 16MB default
        
        if content_length and content_length > max_size:
            return False, f"Request too large: {content_length} bytes"
        
        return True, ""
    
    def _block_ip(self, ip_address: str, reason: str, duration: int):
        """Block IP address for specified duration"""
        self.blocked_ips.add(ip_address)
        
        if self.redis_client:
            key = f"ddos:blocked:{ip_address}"
            self.redis_client.setex(key, duration, reason)
        
        logger.warning(f"IP blocked: {ip_address} for {duration}s - {reason}")
    
    def _is_legitimate_bot(self, user_agent: str) -> bool:
        """Check if bot is from legitimate sources"""
        legitimate_bots = [
            'Googlebot',
            'Bingbot',
            'Slurp',  # Yahoo
            'DuckDuckBot',
            'facebookexternalhit',
            'Twitterbot'
        ]
        
        return any(bot in user_agent for bot in legitimate_bots)
    
    def is_ip_blocked(self, ip_address: str) -> tuple[bool, str]:
        """Check if IP is currently blocked"""
        if ip_address in self.blocked_ips:
            if self.redis_client:
                key = f"ddos:blocked:{ip_address}"
                reason = self.redis_client.get(key)
                if reason:
                    return True, reason.decode('utf-8')
                else:
                    # Block expired
                    self.blocked_ips.discard(ip_address)
                    return False, ""
            return True, "IP blocked"
        
        return False, ""
    
    def analyze_request(self, ip_address: str, user_agent: str, path: str, content_length: int) -> tuple[bool, str]:
        """Comprehensive request analysis"""
        
        # Check if IP is already blocked
        is_blocked, block_reason = self.is_ip_blocked(ip_address)
        if is_blocked:
            return False, f"IP blocked: {block_reason}"
        
        # Run all checks
        checks = [
            lambda: self.check_request_flood(ip_address),
            lambda: self.check_pattern_analysis(ip_address, user_agent, path),
            lambda: self.check_geographic_anomalies(ip_address),
            lambda: self.check_request_size(content_length)
        ]
        
        for check in checks:
            try:
                allowed, reason = check()
                if not allowed:
                    return False, reason
            except Exception as e:
                logger.error(f"DDoS check error: {str(e)}")
                continue
        
        return True, ""

class InputSanitizer:
    """Input sanitization and validation"""
    
    @staticmethod
    def sanitize_sql_injection(input_string: str) -> str:
        """Remove potential SQL injection patterns"""
        if not input_string:
            return input_string
        
        # Remove or escape dangerous patterns
        dangerous_patterns = [
            r"('|(\\'))+.*(\s+|\s*)(union|UNION)",
            r"('|(\\'))+.*(\s+|\s*)(select|SELECT)",
            r"('|(\\'))+.*(\s+|\s*)(insert|INSERT)",
            r"('|(\\'))+.*(\s+|\s*)(update|UPDATE)",
            r"('|(\\'))+.*(\s+|\s*)(delete|DELETE)",
            r"('|(\\'))+.*(\s+|\s*)(drop|DROP)",
            r"('|(\\'))+.*(\s+|\s*)(exec|EXEC)",
            r"(\s+|\s*)(or|OR)(\s+|\s*)('|\d+)(\s+|\s*)=(\s+|\s*)('|\d+)",
            r"(\s+|\s*)(and|AND)(\s+|\s*)('|\d+)(\s+|\s*)=(\s+|\s*)('|\d+)"
        ]
        
        sanitized = input_string
        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, '', sanitized)
        
        return sanitized
    
    @staticmethod
    def sanitize_xss(input_string: str) -> str:
        """Remove potential XSS patterns"""
        if not input_string:
            return input_string
        
        # Remove dangerous HTML/JavaScript patterns
        xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'<iframe[^>]*>.*?</iframe>',
            r'<object[^>]*>.*?</object>',
            r'<embed[^>]*>.*?</embed>',
            r'<link[^>]*>',
            r'<meta[^>]*>'
        ]
        
        sanitized = input_string
        for pattern in xss_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        # Escape remaining HTML entities
        html_escape_table = {
            "&": "&amp;",
            '"': "&quot;",
            "'": "&#x27;",
            ">": "&gt;",
            "<": "&lt;",
        }
        
        for char, escape in html_escape_table.items():
            sanitized = sanitized.replace(char, escape)
        
        return sanitized
    
    @staticmethod
    def validate_nhs_number(nhs_number: str) -> bool:
        """Validate NHS number format and checksum"""
        if not nhs_number or len(nhs_number) != 10:
            return False
        
        if not nhs_number.isdigit():
            return False
        
        # Calculate check digit using Modulus 11
        total = 0
        for i, digit in enumerate(nhs_number[:9]):
            total += int(digit) * (10 - i)
        
        remainder = total % 11
        check_digit = 11 - remainder
        
        if check_digit == 11:
            check_digit = 0
        elif check_digit == 10:
            return False  # Invalid NHS number
        
        return int(nhs_number[9]) == check_digit
    
    @staticmethod
    def sanitize_healthcare_data(data: dict) -> dict:
        """Sanitize healthcare-specific data"""
        sanitized = {}
        
        for key, value in data.items():
            if isinstance(value, str):
                # Apply both SQL injection and XSS protection
                sanitized_value = InputSanitizer.sanitize_sql_injection(value)
                sanitized_value = InputSanitizer.sanitize_xss(sanitized_value)
                
                # Additional healthcare data validation
                if key.lower() in ['nhs_number', 'patient_id']:
                    if not InputSanitizer.validate_nhs_number(sanitized_value):
                        sanitized_value = None
                
                sanitized[key] = sanitized_value
            elif isinstance(value, dict):
                sanitized[key] = InputSanitizer.sanitize_healthcare_data(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    InputSanitizer.sanitize_healthcare_data(item) if isinstance(item, dict)
                    else InputSanitizer.sanitize_xss(str(item)) if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized

# Initialize DDoS protection
ddos_protection = DDoSProtection()
input_sanitizer = InputSanitizer()

def ddos_protection_middleware():
    """DDoS protection middleware function"""
    if request.endpoint == 'health_check':
        return None
    
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    path = request.path
    content_length = request.content_length or 0
    
    # Analyze request for DDoS patterns
    allowed, reason = ddos_protection.analyze_request(ip_address, user_agent, path, content_length)
    
    if not allowed:
        logger.warning(f"DDoS protection blocked request from {ip_address}: {reason}")
        return jsonify({
            'error': 'Request blocked by security system',
            'reason': 'Suspicious activity detected'
        }), 429
    
    return None

def input_sanitization_middleware():
    """Input sanitization middleware"""
    if request.method in ['POST', 'PUT', 'PATCH']:
        if request.is_json:
            try:
                # Get JSON data
                data = request.get_json()
                if data:
                    # Sanitize input data
                    sanitized_data = input_sanitizer.sanitize_healthcare_data(data)
                    
                    # Store sanitized data for use in routes
                    g.sanitized_data = sanitized_data
                    
                    # Log if sanitization made changes
                    if data != sanitized_data:
                        logger.info(f"Input sanitization applied for {request.endpoint}")
                        
            except Exception as e:
                logger.error(f"Input sanitization error: {str(e)}")
                return jsonify({'error': 'Invalid input data'}), 400
    
    return None

def enhanced_security_middleware():
    """Enhanced security middleware combining all protections"""
    
    # Skip for health check
    if request.endpoint == 'health_check':
        return None
    
    # Apply DDoS protection
    ddos_result = ddos_protection_middleware()
    if ddos_result:
        return ddos_result
    
    # Apply input sanitization
    sanitization_result = input_sanitization_middleware()
    if sanitization_result:
        return sanitization_result
    
    return None
