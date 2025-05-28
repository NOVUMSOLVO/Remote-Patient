"""
Security Performance Optimization
Optimizes security components for production deployment
"""

import time
import threading
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional
import redis
import json
from datetime import datetime, timedelta
from flask import current_app
from app.utils.security import SecurityManager, SessionManager, RateLimiter
from app.utils.encryption import EncryptionManager
from app.utils.security_monitor import security_monitor
import logging


class SecurityPerformanceOptimizer:
    """Optimize security components for production performance"""
    
    def __init__(self):
        self.redis_client = None
        self.thread_pool = ThreadPoolExecutor(max_workers=10)
        self.cache_enabled = False
        self.logger = logging.getLogger(__name__)
        
        # Performance metrics
        self.metrics = {
            'encryption_operations': 0,
            'authentication_operations': 0,
            'session_operations': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'avg_response_time': 0.0
        }
        
        self._initialize_cache()
    
    def _initialize_cache(self) -> None:
        """Initialize Redis cache for security operations"""
        try:
            redis_config = current_app.config.get('REDIS_CONFIG', {})
            if redis_config:
                self.redis_client = redis.Redis(
                    host=redis_config.get('host', 'localhost'),
                    port=redis_config.get('port', 6379),
                    db=redis_config.get('db', 0),
                    password=redis_config.get('password'),
                    decode_responses=True
                )
                # Test connection
                self.redis_client.ping()
                self.cache_enabled = True
                self.logger.info("Redis cache initialized successfully")
            else:
                self.logger.info("Redis not configured, caching disabled")
        except Exception as e:
            self.logger.warning(f"Redis cache initialization failed: {str(e)}")
            self.redis_client = None
            self.cache_enabled = False
    
    def optimize_encryption_operations(self) -> None:
        """Optimize encryption/decryption operations"""
        
        # Implement encryption key caching
        if self.cache_enabled:
            self._cache_encryption_keys()
        
        # Pre-warm encryption objects
        self._prewarm_encryption_objects()
        
        # Implement batch encryption for multiple operations
        self._setup_batch_encryption()
    
    def _cache_encryption_keys(self) -> None:
        """Cache frequently used encryption keys"""
        if not self.cache_enabled or not self.redis_client:
            return
            
        try:
            # Simplified version - in practice would integrate with EncryptionManager
            dummy_keys = {'key1': 'value1', 'key2': 'value2'}
            for key_id, key_data in dummy_keys.items():
                cache_key = f"enc_key:{key_id}"
                self.redis_client.setex(
                    cache_key, 
                    3600,  # 1 hour in seconds
                    json.dumps({'data': key_data})
                )
            
            self.logger.info(f"Cached {len(dummy_keys)} encryption keys")
            
        except Exception as e:
            self.logger.error(f"Encryption key caching failed: {str(e)}")
    
    def _prewarm_encryption_objects(self) -> None:
        """Pre-warm encryption objects to reduce initialization time"""
        try:
            # Pre-initialize Fernet objects
            from cryptography.fernet import Fernet
            
            # Create a pool of ready-to-use Fernet objects
            self.fernet_pool = []
            for _ in range(5):  # Pool of 5 objects
                key = Fernet.generate_key()
                fernet_obj = Fernet(key)
                self.fernet_pool.append((key, fernet_obj))
            
            self.logger.info("Encryption objects pre-warmed")
            
        except Exception as e:
            self.logger.error(f"Encryption pre-warming failed: {str(e)}")
    
    def _setup_batch_encryption(self) -> None:
        """Setup batch encryption for improved performance"""
        self.encryption_queue = []
        self.encryption_results = {}
        
        # Start background worker for batch processing
        threading.Thread(
            target=self._process_encryption_batch,
            daemon=True
        ).start()
    
    def _process_encryption_batch(self) -> None:
        """Process encryption operations in batches"""
        while True:
            try:
                if len(self.encryption_queue) >= 10:  # Process in batches of 10
                    batch = self.encryption_queue[:10]
                    self.encryption_queue = self.encryption_queue[10:]
                    
                    # Process batch in parallel
                    futures = []
                    for operation in batch:
                        future = self.thread_pool.submit(
                            self._execute_encryption_operation,
                            operation
                        )
                        futures.append((operation['id'], future))
                    
                    # Collect results
                    for op_id, future in futures:
                        try:
                            result = future.result(timeout=5)
                            self.encryption_results[op_id] = result
                        except Exception as e:
                            self.encryption_results[op_id] = {'error': str(e)}
                
                time.sleep(0.1)  # Check every 100ms
                
            except Exception as e:
                self.logger.error(f"Batch encryption processing error: {str(e)}")
    
    def _execute_encryption_operation(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single encryption operation"""
        start_time = time.time()
        
        try:
            if operation['type'] == 'encrypt':
                result = self._encrypt_data_optimized(operation['data'])
            elif operation['type'] == 'decrypt':
                result = self._decrypt_data_optimized(operation['data'])
            else:
                raise ValueError(f"Unknown operation type: {operation['type']}")
            
            execution_time = time.time() - start_time
            self.metrics['encryption_operations'] += 1
            
            return {
                'success': True,
                'result': result,
                'execution_time': execution_time
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'execution_time': time.time() - start_time
            }
    
    def _encrypt_data_optimized(self, data: str) -> str:
        """Optimized data encryption using object pool"""
        if self.fernet_pool:
            key, fernet_obj = self.fernet_pool.pop()
            try:
                encrypted = fernet_obj.encrypt(data.encode())
                return encrypted.decode()
            finally:
                self.fernet_pool.append((key, fernet_obj))
        else:
            # Fallback to standard encryption
            from cryptography.fernet import Fernet
            key = Fernet.generate_key()
            fernet_obj = Fernet(key)
            return fernet_obj.encrypt(data.encode()).decode()
    
    def _decrypt_data_optimized(self, encrypted_data: str) -> str:
        """Optimized data decryption"""
        # Implementation would depend on having the correct key
        # This is a simplified version
        return "decrypted_data"
    
    def optimize_session_management(self) -> None:
        """Optimize session management operations"""
        
        if self.cache_enabled:
            self._cache_active_sessions()
            self._setup_session_cleanup()
        
        self._optimize_session_validation()
    
    def _cache_active_sessions(self) -> None:
        """Cache active sessions in Redis for fast lookup"""
        try:
            session_manager = SessionManager()
            active_sessions = session_manager.get_active_sessions()
            
            for session in active_sessions:
                cache_key = f"session:{session['token']}"
                session_data = {
                    'user_id': session['user_id'],
                    'expires_at': session['expires_at'].isoformat(),
                    'ip_address': session.get('ip_address'),
                    'last_activity': session.get('last_activity', datetime.utcnow()).isoformat()
                }
                
                # Cache with TTL matching session expiry
                ttl = session['expires_at'] - datetime.utcnow()
                if ttl.total_seconds() > 0:
                    self.redis_client.setex(
                        cache_key,
                        int(ttl.total_seconds()),
                        json.dumps(session_data)
                    )
            
            self.logger.info(f"Cached {len(active_sessions)} active sessions")
            
        except Exception as e:
            self.logger.error(f"Session caching failed: {str(e)}")
    
    def _setup_session_cleanup(self) -> None:
        """Setup automated session cleanup"""
        def cleanup_expired_sessions():
            while True:
                try:
                    # Clean up expired sessions every 5 minutes
                    time.sleep(300)
                    
                    if self.cache_enabled:
                        # Get all session keys
                        session_keys = self.redis_client.keys("session:*")
                        
                        for key in session_keys:
                            session_data = self.redis_client.get(key)
                            if session_data:
                                data = json.loads(session_data)
                                expires_at = datetime.fromisoformat(data['expires_at'])
                                
                                if expires_at < datetime.utcnow():
                                    self.redis_client.delete(key)
                    
                except Exception as e:
                    self.logger.error(f"Session cleanup error: {str(e)}")
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=cleanup_expired_sessions, daemon=True)
        cleanup_thread.start()
    
    def _optimize_session_validation(self) -> None:
        """Optimize session validation with caching"""
        self.session_validation_cache = {}
        self.cache_ttl = 60  # Cache validation results for 1 minute
    
    def validate_session_optimized(self, token: str) -> bool:
        """Optimized session validation with caching"""
        start_time = time.time()
        
        # Check local cache first
        if token in self.session_validation_cache:
            cached_result, cached_time = self.session_validation_cache[token]
            if time.time() - cached_time < self.cache_ttl:
                self.metrics['cache_hits'] += 1
                return cached_result
        
        # Check Redis cache
        if self.cache_enabled:
            cache_key = f"session:{token}"
            session_data = self.redis_client.get(cache_key)
            
            if session_data:
                data = json.loads(session_data)
                expires_at = datetime.fromisoformat(data['expires_at'])
                is_valid = expires_at > datetime.utcnow()
                
                # Cache result locally
                self.session_validation_cache[token] = (is_valid, time.time())
                self.metrics['cache_hits'] += 1
                self.metrics['session_operations'] += 1
                
                return is_valid
        
        # Fallback to database lookup
        self.metrics['cache_misses'] += 1
        session_manager = SessionManager()
        is_valid = session_manager.validate_session(token)
        
        # Cache the result
        self.session_validation_cache[token] = (is_valid, time.time())
        self.metrics['session_operations'] += 1
        
        execution_time = time.time() - start_time
        self._update_avg_response_time(execution_time)
        
        return is_valid
    
    def optimize_rate_limiting(self) -> None:
        """Optimize rate limiting operations"""
        
        if self.cache_enabled:
            self._setup_distributed_rate_limiting()
        
        self._optimize_rate_limit_checks()
    
    def _setup_distributed_rate_limiting(self) -> None:
        """Setup distributed rate limiting using Redis"""
        self.rate_limit_scripts = {
            'sliding_window': """
                local key = KEYS[1]
                local window = tonumber(ARGV[1])
                local limit = tonumber(ARGV[2])
                local now = tonumber(ARGV[3])
                
                -- Remove expired entries
                redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
                
                -- Count current requests
                local current = redis.call('ZCARD', key)
                
                if current < limit then
                    -- Add current request
                    redis.call('ZADD', key, now, now)
                    redis.call('EXPIRE', key, window)
                    return {1, limit - current - 1}
                else
                    return {0, 0}
                end
            """
        }
        
        # Register Lua script for atomic operations
        self.sliding_window_script = self.redis_client.register_script(
            self.rate_limit_scripts['sliding_window']
        )
    
    def _optimize_rate_limit_checks(self) -> None:
        """Optimize rate limit checking with Redis"""
        pass
    
    def check_rate_limit_optimized(self, identifier: str, limit: int, window: int) -> bool:
        """Optimized rate limiting check"""
        if not self.cache_enabled:
            # Fallback to in-memory rate limiting
            rate_limiter = RateLimiter()
            return rate_limiter.is_allowed(identifier, limit, window)
        
        try:
            now = int(time.time())
            result = self.sliding_window_script(
                keys=[f"rate_limit:{identifier}"],
                args=[window, limit, now]
            )
            
            allowed, remaining = result
            return bool(allowed)
            
        except Exception as e:
            self.logger.error(f"Optimized rate limiting failed: {str(e)}")
            # Fallback to standard rate limiting
            rate_limiter = RateLimiter()
            return rate_limiter.is_allowed(identifier, limit, window)
    
    def optimize_security_monitoring(self) -> None:
        """Optimize security monitoring operations"""
        
        # Setup background monitoring
        self._setup_background_monitoring()
        
        # Optimize alert processing
        self._optimize_alert_processing()
    
    def _setup_background_monitoring(self) -> None:
        """Setup background security monitoring"""
        def background_monitor():
            while True:
                try:
                    # Run security checks every 30 seconds
                    time.sleep(30)
                    
                    # Check for security threats
                    self._check_security_threats_optimized()
                    
                    # Update threat intelligence
                    self._update_threat_intelligence()
                    
                except Exception as e:
                    self.logger.error(f"Background monitoring error: {str(e)}")
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=background_monitor, daemon=True)
        monitor_thread.start()
    
    def _check_security_threats_optimized(self) -> None:
        """Optimized security threat checking"""
        if self.cache_enabled:
            # Use Redis for fast threat pattern matching
            recent_events = self._get_recent_security_events()
            self._analyze_threat_patterns(recent_events)
    
    def _get_recent_security_events(self) -> List[Dict[str, Any]]:
        """Get recent security events from cache"""
        if not self.cache_enabled:
            return []
        
        try:
            # Get events from last 5 minutes
            cutoff_time = int((datetime.utcnow() - timedelta(minutes=5)).timestamp())
            
            event_keys = self.redis_client.zrangebyscore(
                'security_events_timeline',
                cutoff_time,
                '+inf'
            )
            
            events = []
            for key in event_keys:
                event_data = self.redis_client.hgetall(f"security_event:{key}")
                if event_data:
                    events.append(event_data)
            
            return events
            
        except Exception as e:
            self.logger.error(f"Failed to get recent security events: {str(e)}")
            return []
    
    def _analyze_threat_patterns(self, events: List[Dict[str, Any]]) -> None:
        """Analyze security events for threat patterns"""
        # Group events by IP address
        ip_events = {}
        for event in events:
            ip = event.get('ip_address')
            if ip:
                if ip not in ip_events:
                    ip_events[ip] = []
                ip_events[ip].append(event)
        
        # Check for suspicious patterns
        for ip, ip_event_list in ip_events.items():
            if len(ip_event_list) > 10:  # More than 10 events in 5 minutes
                self._trigger_threat_alert(ip, 'high_activity', ip_event_list)
    
    def _trigger_threat_alert(self, ip: str, threat_type: str, events: List[Dict[str, Any]]) -> None:
        """Trigger optimized threat alert"""
        alert_data = {
            'ip_address': ip,
            'threat_type': threat_type,
            'event_count': len(events),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Queue alert for background processing
        if self.cache_enabled:
            self.redis_client.lpush('threat_alerts', json.dumps(alert_data))
    
    def _optimize_alert_processing(self) -> None:
        """Optimize alert processing with background workers"""
        def process_alerts():
            while True:
                try:
                    if self.cache_enabled:
                        # Process alerts from queue
                        alert_data = self.redis_client.brpop('threat_alerts', timeout=1)
                        if alert_data:
                            _, alert_json = alert_data
                            alert = json.loads(alert_json)
                            security_monitor.handle_threat_alert(alert)
                    
                    time.sleep(0.1)
                    
                except Exception as e:
                    self.logger.error(f"Alert processing error: {str(e)}")
        
        # Start alert processing thread
        alert_thread = threading.Thread(target=process_alerts, daemon=True)
        alert_thread.start()
    
    def _update_threat_intelligence(self) -> None:
        """Update threat intelligence data"""
        try:
            # Get current threat intelligence
            intel = security_monitor.get_threat_intelligence()
            
            if self.cache_enabled:
                # Cache threat intelligence
                self.redis_client.setex(
                    'threat_intelligence',
                    timedelta(minutes=5),
                    json.dumps(intel)
                )
        except Exception as e:
            self.logger.error(f"Threat intelligence update failed: {str(e)}")
    
    def _update_avg_response_time(self, execution_time: float) -> None:
        """Update average response time metric"""
        current_avg = self.metrics['avg_response_time']
        total_ops = sum([
            self.metrics['encryption_operations'],
            self.metrics['authentication_operations'],
            self.metrics['session_operations']
        ])
        
        if total_ops > 0:
            self.metrics['avg_response_time'] = (
                (current_avg * (total_ops - 1)) + execution_time
            ) / total_ops
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        cache_hit_rate = 0.0
        total_cache_ops = self.metrics['cache_hits'] + self.metrics['cache_misses']
        if total_cache_ops > 0:
            cache_hit_rate = self.metrics['cache_hits'] / total_cache_ops * 100
        
        return {
            **self.metrics,
            'cache_hit_rate': cache_hit_rate,
            'cache_enabled': self.cache_enabled,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def optimize_all(self) -> None:
        """Run all optimization procedures"""
        self.logger.info("Starting security performance optimization...")
        
        self.optimize_encryption_operations()
        self.optimize_session_management()
        self.optimize_rate_limiting()
        self.optimize_security_monitoring()
        
        self.logger.info("Security performance optimization completed")


# Global optimizer instance
security_optimizer = SecurityPerformanceOptimizer()
