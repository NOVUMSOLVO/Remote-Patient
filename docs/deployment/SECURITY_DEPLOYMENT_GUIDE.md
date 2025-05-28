# Security Infrastructure Deployment Guide

## Remote Patient Monitoring System - Security Deployment

### Version: 1.0 (Production Ready)
### Date: May 28, 2025
### Deployment Target: Q3 2025

---

## Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Environment Setup](#environment-setup)
3. [Security Component Installation](#security-component-installation)
4. [Configuration Management](#configuration-management)
5. [Testing & Validation](#testing--validation)
6. [Go-Live Procedures](#go-live-procedures)
7. [Post-Deployment Monitoring](#post-deployment-monitoring)
8. [Rollback Procedures](#rollback-procedures)

---

## Pre-Deployment Checklist

### Infrastructure Requirements ✅

#### Server Specifications
- **Production Server**: 32GB RAM, 8 CPU cores, 1TB SSD
- **Database Server**: 64GB RAM, 16 CPU cores, 2TB SSD (encrypted)
- **Redis Cache**: 16GB RAM, 4 CPU cores, 500GB SSD
- **Load Balancer**: 16GB RAM, 4 CPU cores, HA configuration

#### Network Requirements
- **Bandwidth**: 1Gbps minimum, 10Gbps recommended
- **Latency**: < 50ms to NHS Digital services
- **Redundancy**: Dual network paths, automatic failover
- **Firewall**: Next-gen firewall with DPI capabilities

#### Security Certificates
- [ ] SSL/TLS certificates from approved CA
- [ ] NHS CIS2 client certificates
- [ ] Code signing certificates
- [ ] Device authentication certificates

### Software Prerequisites ✅

```bash
# Operating System
Ubuntu 20.04 LTS (Focal Fossa) - Hardened

# Required Software Versions
Python 3.9.16
PostgreSQL 13.11 with TDE
Redis 6.2.12 with encryption
Nginx 1.20.2
Node.js 18.16.0 (for frontend)

# Security Tools
fail2ban 0.11.2
ufw (Uncomplicated Firewall)
ClamAV antivirus
AIDE (intrusion detection)
```

### Compliance Verification ✅

- [ ] NHS Digital Security Clearance
- [ ] Data Protection Impact Assessment (DPIA) approved
- [ ] Clinical Risk Assessment completed
- [ ] Penetration testing passed
- [ ] Security architecture review approved
- [ ] NHS Information Governance Toolkit completed

---

## Environment Setup

### 1. Server Hardening

#### Base System Configuration
```bash
#!/bin/bash
# server_hardening.sh

# Update system
sudo apt update && sudo apt upgrade -y

# Install security updates automatically
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades

# Configure firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp    # SSH (temporary)
sudo ufw allow 80/tcp    # HTTP (redirect to HTTPS)
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable

# Install and configure fail2ban
sudo apt install fail2ban -y
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Configure SSH security
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Install intrusion detection
sudo apt install aide -y
sudo aideinit
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Setup log rotation
sudo logrotate -f /etc/logrotate.conf

echo "Server hardening completed"
```

#### NHS-Specific Security Configuration
```bash
#!/bin/bash
# nhs_security_config.sh

# Install NHS approved antivirus
sudo apt install clamav clamav-daemon -y
sudo freshclam
sudo systemctl enable clamav-daemon
sudo systemctl start clamav-daemon

# Configure audit logging (for NHS compliance)
sudo apt install auditd -y
echo "
# NHS Security Audit Rules
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /var/log/auth.log -p wa -k authentication
-w /var/log/secure -p wa -k authentication
" | sudo tee -a /etc/audit/rules.d/nhs-security.rules

sudo systemctl restart auditd

# Setup NHS time synchronization
sudo apt install ntp -y
echo "server time.nhs.uk iburst" | sudo tee -a /etc/ntp.conf
sudo systemctl restart ntp

echo "NHS security configuration completed"
```

### 2. Database Setup

#### PostgreSQL Installation with Encryption
```bash
#!/bin/bash
# database_setup.sh

# Install PostgreSQL 13
sudo apt install postgresql-13 postgresql-contrib-13 -y

# Configure PostgreSQL for security
sudo -u postgres psql << EOF
-- Create database user
CREATE USER rpm_user WITH ENCRYPTED PASSWORD 'secure_password_256_bits';

-- Create database with encryption
CREATE DATABASE rpm_db 
    WITH OWNER rpm_user
    ENCODING 'UTF8'
    LC_COLLATE 'en_GB.UTF-8'
    LC_CTYPE 'en_GB.UTF-8'
    TEMPLATE template0;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE rpm_db TO rpm_user;

-- Enable row-level security
\c rpm_db
ALTER DATABASE rpm_db SET row_security = on;

-- Create audit schema
CREATE SCHEMA IF NOT EXISTS audit;
GRANT USAGE ON SCHEMA audit TO rpm_user;
GRANT CREATE ON SCHEMA audit TO rpm_user;

\q
EOF

# Configure PostgreSQL security settings
sudo tee -a /etc/postgresql/13/main/postgresql.conf << EOF

# NHS Security Configuration
ssl = on
ssl_cert_file = '/etc/ssl/certs/postgresql-server.crt'
ssl_key_file = '/etc/ssl/private/postgresql-server.key'
ssl_ciphers = 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'
ssl_min_protocol_version = 'TLSv1.2'

# Logging for audit compliance
log_destination = 'stderr,csvlog'
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_rotation_age = 1d
log_rotation_size = 100MB
log_connections = on
log_disconnections = on
log_checkpoints = on
log_lock_waits = on
log_statement = 'all'
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '

# Performance and security
shared_preload_libraries = 'pg_stat_statements'
max_connections = 100
shared_buffers = 8GB
effective_cache_size = 24GB
maintenance_work_mem = 2GB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 80MB
min_wal_size = 2GB
max_wal_size = 8GB
EOF

# Configure PostgreSQL client authentication
sudo tee /etc/postgresql/13/main/pg_hba.conf << EOF
# NHS Security Configuration
# TYPE  DATABASE        USER            ADDRESS                 METHOD

# Local connections
local   all             postgres                                peer
local   all             all                                     md5

# SSL connections only for remote access
hostssl rpm_db          rpm_user        0.0.0.0/0               md5
hostssl all             all             127.0.0.1/32            md5
hostssl all             all             ::1/128                 md5

# Reject non-SSL connections
host    all             all             0.0.0.0/0               reject
EOF

sudo systemctl restart postgresql
sudo systemctl enable postgresql

echo "PostgreSQL setup completed with NHS security configuration"
```

### 3. Redis Cache Setup

#### Redis Installation with Encryption
```bash
#!/bin/bash
# redis_setup.sh

# Install Redis
sudo apt install redis-server -y

# Configure Redis for security
sudo tee /etc/redis/redis.conf << EOF
# NHS Security Configuration for Redis
bind 127.0.0.1
port 6379
requirepass redis_secure_password_256_bits

# Enable TLS
tls-port 6380
tls-cert-file /etc/ssl/certs/redis-server.crt
tls-key-file /etc/ssl/private/redis-server.key
tls-ca-cert-file /etc/ssl/certs/ca-certificates.crt
tls-ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256

# Security settings
protected-mode yes
tcp-keepalive 300
timeout 300
tcp-backlog 511

# Logging for audit
syslog-enabled yes
syslog-ident redis
syslog-facility local0
loglevel notice

# Performance settings
maxmemory 8gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000

# Disable dangerous commands
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command KEYS ""
rename-command CONFIG "CONFIG_a8f9c2e1d4b7f3a9"
rename-command SHUTDOWN "SHUTDOWN_d2c5a8f1e9b4c7d6"
rename-command DEBUG ""
rename-command EVAL ""
EOF

sudo systemctl restart redis-server
sudo systemctl enable redis-server

echo "Redis setup completed with NHS security configuration"
```

---

## Security Component Installation

### 1. Application Installation

#### Clone and Setup Application
```bash
#!/bin/bash
# app_installation.sh

# Create application user
sudo useradd -m -s /bin/bash rpm-app
sudo usermod -aG sudo rpm-app

# Create application directory
sudo mkdir -p /opt/rpm-system
sudo chown rpm-app:rpm-app /opt/rpm-system

# Switch to application user
sudo -u rpm-app bash << 'EOF'
cd /opt/rpm-system

# Clone repository (assuming it's available)
git clone https://github.com/your-org/remote-patient-monitoring.git .

# Create virtual environment
python3.9 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -r backend/requirements.txt

# Install additional security packages
pip install gunicorn supervisor

# Create logs directory
mkdir -p logs/security
mkdir -p logs/audit
mkdir -p logs/performance

# Set permissions
chmod 750 logs/
chmod 750 logs/security/
chmod 750 logs/audit/
EOF

echo "Application installation completed"
```

#### Security Keys Generation
```bash
#!/bin/bash
# generate_security_keys.sh

cd /opt/rpm-system

# Generate encryption keys
python3 << 'EOF'
import secrets
import base64
from cryptography.fernet import Fernet

# Generate main encryption key
encryption_key = Fernet.generate_key()
print(f"ENCRYPTION_KEY={encryption_key.decode()}")

# Generate secret key for Flask
secret_key = secrets.token_urlsafe(32)
print(f"SECRET_KEY={secret_key}")

# Generate JWT secret
jwt_secret = secrets.token_urlsafe(32)
print(f"JWT_SECRET_KEY={jwt_secret}")

# Generate API keys
api_key = secrets.token_urlsafe(32)
print(f"API_KEY={api_key}")

# Generate session key
session_key = secrets.token_urlsafe(32)
print(f"SESSION_KEY={session_key}")
EOF

echo "Security keys generated. Store them securely!"
```

### 2. Environment Configuration

#### Production Environment File
```bash
#!/bin/bash
# create_production_env.sh

sudo -u rpm-app tee /opt/rpm-system/.env << 'EOF'
# Production Environment Configuration
FLASK_ENV=production
FLASK_DEBUG=False

# Database Configuration
DATABASE_URL=postgresql://rpm_user:secure_password_256_bits@localhost:5432/rpm_db

# Redis Configuration
REDIS_URL=redis://:redis_secure_password_256_bits@localhost:6379/0

# Security Configuration
SECRET_KEY=your_generated_secret_key_here
ENCRYPTION_KEY=your_generated_encryption_key_here
JWT_SECRET_KEY=your_generated_jwt_secret_here
SESSION_KEY=your_generated_session_key_here

# NHS CIS2 Configuration
NHS_CIS2_CLIENT_ID=your_nhs_client_id
NHS_CIS2_CLIENT_SECRET=your_nhs_client_secret
NHS_CIS2_AUTH_URL=https://am.nhsint.auth-ptl.cis2.spineservices.nhs.uk/openam/oauth2/authorize
NHS_CIS2_TOKEN_URL=https://am.nhsint.auth-ptl.cis2.spineservices.nhs.uk/openam/oauth2/access_token
NHS_CIS2_USER_INFO_URL=https://am.nhsint.auth-ptl.cis2.spineservices.nhs.uk/openam/oauth2/userinfo

# Security Settings
SECURITY_ENHANCED=true
MFA_REQUIRED=true
MFA_ISSUER=NHS-RPM-System
SESSION_TIMEOUT_MINUTES=30
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=30

# Encryption Settings
ENCRYPTION_AT_REST_ENABLED=true
PII_ENCRYPTION_ENABLED=true
HEALTH_DATA_ENCRYPTION_ENABLED=true

# Audit Settings
AUDIT_LOG_RETENTION_DAYS=2555
AUDIT_LOG_ENCRYPTION=true
SECURITY_MONITORING_ENABLED=true

# Rate Limiting
RATELIMIT_STORAGE_URL=redis://:redis_secure_password_256_bits@localhost:6379/1
RATELIMIT_DEFAULT=100 per hour

# Monitoring
SECURITY_ALERTS_EMAIL=security@yourorg.nhs.uk
SECURITY_ALERTS_ENABLED=true
REAL_TIME_ALERTS=true

# SSL/TLS
SSL_CERT_PATH=/etc/ssl/certs/rpm-system.crt
SSL_KEY_PATH=/etc/ssl/private/rpm-system.key

# Logging
LOG_LEVEL=INFO
LOG_TO_FILE=true
LOG_FILE_PATH=/opt/rpm-system/logs/application.log
SECURITY_LOG_PATH=/opt/rpm-system/logs/security/security.log
AUDIT_LOG_PATH=/opt/rpm-system/logs/audit/audit.log
EOF

# Set secure permissions on environment file
sudo chmod 600 /opt/rpm-system/.env
sudo chown rpm-app:rpm-app /opt/rpm-system/.env

echo "Production environment file created"
```

### 3. Database Migration

#### Run Security Database Migrations
```bash
#!/bin/bash
# database_migration.sh

cd /opt/rpm-system
source venv/bin/activate

# Set environment
export FLASK_APP=backend/app
export FLASK_ENV=production

# Initialize database
flask db init

# Create migration for security features
flask db migrate -m "Add security features and NHS compliance"

# Apply migrations
flask db upgrade

# Create initial security data
python3 << 'EOF'
from backend.app import create_app
from backend.app.models import db, User, SecurityAuditLog
from backend.app.utils.security import SecurityManager

app = create_app('production')
with app.app_context():
    # Create security manager
    security_manager = SecurityManager()
    
    # Create admin user
    admin_user = User(
        email='admin@yourorg.nhs.uk',
        first_name='System',
        last_name='Administrator',
        role='super_admin',
        nhs_verified=True,
        mfa_enabled=True
    )
    admin_user.password_hash = security_manager.hash_password('AdminPassword123!')
    
    db.session.add(admin_user)
    db.session.commit()
    
    print("Initial security data created")
EOF

echo "Database migration completed"
```

---

## Configuration Management

### 1. Web Server Configuration

#### Nginx Configuration
```bash
#!/bin/bash
# nginx_configuration.sh

# Install Nginx
sudo apt install nginx -y

# Create Nginx configuration for RPM system
sudo tee /etc/nginx/sites-available/rpm-system << 'EOF'
# NHS Remote Patient Monitoring System
# Security-hardened Nginx configuration

upstream rpm_backend {
    server 127.0.0.1:5000 fail_timeout=10s max_fails=3;
    server 127.0.0.1:5001 backup;
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name your-domain.nhs.uk;
    return 301 https://$server_name$request_uri;
}

# Main HTTPS server
server {
    listen 443 ssl http2;
    server_name your-domain.nhs.uk;
    
    # SSL Configuration (NHS Standards)
    ssl_certificate /etc/ssl/certs/rpm-system.crt;
    ssl_certificate_key /etc/ssl/private/rpm-system.key;
    ssl_certificate /etc/ssl/certs/intermediate.crt;
    
    # SSL Security Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers on;
    ssl_ecdh_curve secp384r1;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # NHS Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';" always;
    add_header X-Permitted-Cross-Domain-Policies none always;
    add_header NHS-Security-Policy "enforced" always;
    
    # Hide Nginx version
    server_tokens off;
    
    # Client settings
    client_max_body_size 10M;
    client_body_timeout 60s;
    client_header_timeout 60s;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    
    # Logging for NHS compliance
    access_log /var/log/nginx/rpm-access.log combined;
    error_log /var/log/nginx/rpm-error.log warn;
    
    # API endpoints
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        
        proxy_pass http://rpm_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        
        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
        
        # Security
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
    
    # Authentication endpoints with stricter rate limiting
    location /api/auth/ {
        limit_req zone=login burst=5 nodelay;
        
        proxy_pass http://rpm_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Static files with caching
    location /static/ {
        alias /opt/rpm-system/frontend/build/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
        add_header X-Content-Type-Options nosniff;
    }
    
    # Frontend application
    location / {
        try_files $uri $uri/ /index.html;
        root /opt/rpm-system/frontend/build;
        index index.html;
        
        # Security headers for frontend
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
    
    # Block access to sensitive files
    location ~ /\.(ht|env|git) {
        deny all;
        return 404;
    }
    
    # Block access to backup files
    location ~ \.(sql|bak|backup|old)$ {
        deny all;
        return 404;
    }
}
EOF

# Enable the site
sudo ln -sf /etc/nginx/sites-available/rpm-system /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
sudo systemctl enable nginx

echo "Nginx configuration completed"
```

### 2. SSL Certificate Setup

#### Let's Encrypt with NHS Domain
```bash
#!/bin/bash
# ssl_certificate_setup.sh

# Install Certbot
sudo apt install certbot python3-certbot-nginx -y

# Request certificate for NHS domain
sudo certbot --nginx -d your-domain.nhs.uk --email security@yourorg.nhs.uk --agree-tos --no-eff-email

# Setup automatic renewal
echo "0 12 * * * /usr/bin/certbot renew --quiet" | sudo crontab -

# Verify certificate
sudo certbot certificates

echo "SSL certificate setup completed"
```

### 3. Application Server Configuration

#### Gunicorn Configuration
```bash
#!/bin/bash
# gunicorn_configuration.sh

# Create Gunicorn configuration
sudo -u rpm-app tee /opt/rpm-system/gunicorn.conf.py << 'EOF'
# Gunicorn configuration for NHS Remote Patient Monitoring

# Server socket
bind = "127.0.0.1:5000"
backlog = 2048

# Worker processes
workers = 4
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

# Restart workers after this many requests
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = "/opt/rpm-system/logs/gunicorn-access.log"
errorlog = "/opt/rpm-system/logs/gunicorn-error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "rpm-system"

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Preload application for better performance
preload_app = True

# User and group
user = "rpm-app"
group = "rpm-app"

# SSL (if terminating SSL at application level)
# keyfile = "/etc/ssl/private/rpm-system.key"
# certfile = "/etc/ssl/certs/rpm-system.crt"
EOF

echo "Gunicorn configuration created"
```

#### Systemd Service Configuration
```bash
#!/bin/bash
# systemd_service_setup.sh

# Create systemd service file
sudo tee /etc/systemd/system/rpm-system.service << 'EOF'
[Unit]
Description=NHS Remote Patient Monitoring System
After=network.target postgresql.service redis-server.service
Requires=postgresql.service redis-server.service

[Service]
Type=notify
User=rpm-app
Group=rpm-app
WorkingDirectory=/opt/rpm-system
ExecStart=/opt/rpm-system/venv/bin/gunicorn --config /opt/rpm-system/gunicorn.conf.py backend.app:create_app()
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=mixed
TimeoutStopSec=30
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/rpm-system/logs
NoNewPrivileges=true
EnvironmentFile=/opt/rpm-system/.env

# Security settings
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable rpm-system.service

echo "Systemd service configuration completed"
```

---

## Testing & Validation

### 1. Security Validation

#### Run Security Validation Script
```bash
#!/bin/bash
# run_security_validation.sh

cd /opt/rpm-system
source venv/bin/activate

echo "Starting comprehensive security validation..."

# Run security validation
python scripts/validate_security.py

# Run security tests
python -m pytest tests/test_security.py -v

# Check SSL configuration
echo "Checking SSL configuration..."
openssl s_client -connect localhost:443 -servername your-domain.nhs.uk

# Test authentication endpoints
echo "Testing authentication endpoints..."
curl -X POST https://your-domain.nhs.uk/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@nhs.uk","password":"invalid"}'

# Test rate limiting
echo "Testing rate limiting..."
for i in {1..15}; do
  curl -s -o /dev/null -w "%{http_code}\n" https://your-domain.nhs.uk/api/health
done

# Test security headers
echo "Testing security headers..."
curl -I https://your-domain.nhs.uk/

echo "Security validation completed"
```

### 2. Performance Testing

#### Load Testing Script
```bash
#!/bin/bash
# performance_testing.sh

# Install Apache Bench for basic load testing
sudo apt install apache2-utils -y

echo "Starting performance tests..."

# Test authentication endpoint
echo "Testing authentication performance..."
ab -n 1000 -c 10 -H "Content-Type: application/json" \
  -p login_data.json \
  https://your-domain.nhs.uk/api/auth/login

# Test API endpoints
echo "Testing API performance..."
ab -n 5000 -c 50 https://your-domain.nhs.uk/api/health

# Test with authentication
echo "Testing authenticated endpoints..."
TOKEN=$(curl -s -X POST https://your-domain.nhs.uk/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourorg.nhs.uk","password":"AdminPassword123!"}' \
  | jq -r '.token')

ab -n 1000 -c 20 -H "Authorization: Bearer $TOKEN" \
  https://your-domain.nhs.uk/api/patients

echo "Performance testing completed"
```

### 3. NHS Compliance Testing

#### Compliance Validation Script
```bash
#!/bin/bash
# nhs_compliance_testing.sh

echo "Starting NHS compliance validation..."

# Check data encryption
echo "Validating data encryption..."
python3 << 'EOF'
from backend.app import create_app
from backend.app.utils.encryption import EncryptionManager

app = create_app('production')
with app.app_context():
    encryption_manager = EncryptionManager()
    
    # Test PII encryption
    test_pii = {"name": "Test Patient", "nhs_number": "1234567890"}
    encrypted = encryption_manager.encrypt_pii(test_pii)
    decrypted = encryption_manager.decrypt_pii(encrypted)
    
    assert decrypted == test_pii
    print("✅ PII encryption working correctly")
    
    # Test health data encryption
    test_health = {"blood_pressure": "120/80", "heart_rate": 72}
    encrypted = encryption_manager.encrypt_health_data(test_health)
    decrypted = encryption_manager.decrypt_health_data(encrypted)
    
    assert decrypted == test_health
    print("✅ Health data encryption working correctly")
EOF

# Check audit logging
echo "Validating audit logging..."
python3 << 'EOF'
from backend.app import create_app
from backend.app.utils.security import AuditLogger

app = create_app('production')
with app.app_context():
    audit_logger = AuditLogger()
    
    # Test audit logging
    result = audit_logger.log_security_event(
        event_type='compliance_test',
        user_id=1,
        ip_address='127.0.0.1',
        details={'test': 'NHS compliance validation'}
    )
    
    assert result is True
    print("✅ Audit logging working correctly")
EOF

# Check NHS CIS2 integration
echo "Validating NHS CIS2 integration..."
curl -s "https://your-domain.nhs.uk/api/auth/nhs-cis2/authorize" | grep -q "nhs"
if [ $? -eq 0 ]; then
    echo "✅ NHS CIS2 integration available"
else
    echo "❌ NHS CIS2 integration not working"
fi

echo "NHS compliance validation completed"
```

---

## Go-Live Procedures

### 1. Pre-Go-Live Checklist

```bash
#!/bin/bash
# pre_golive_checklist.sh

echo "=== NHS Remote Patient Monitoring System ==="
echo "=== Pre Go-Live Security Checklist ==="
echo

# Function to check and report status
check_status() {
    if eval "$1"; then
        echo "✅ $2"
        return 0
    else
        echo "❌ $2"
        return 1
    fi
}

FAILED_CHECKS=0

# Security checks
echo "🔒 SECURITY CHECKS"
echo "===================="

check_status "systemctl is-active postgresql --quiet" "PostgreSQL database running"
[ $? -ne 0 ] && ((FAILED_CHECKS++))

check_status "systemctl is-active redis-server --quiet" "Redis cache running"
[ $? -ne 0 ] && ((FAILED_CHECKS++))

check_status "systemctl is-active nginx --quiet" "Nginx web server running"
[ $? -ne 0 ] && ((FAILED_CHECKS++))

check_status "systemctl is-active rpm-system --quiet" "RPM application running"
[ $? -ne 0 ] && ((FAILED_CHECKS++))

check_status "curl -s -k https://localhost/health | grep -q healthy" "Application health check"
[ $? -ne 0 ] && ((FAILED_CHECKS++))

check_status "test -f /etc/ssl/certs/rpm-system.crt" "SSL certificate present"
[ $? -ne 0 ] && ((FAILED_CHECKS++))

check_status "openssl x509 -in /etc/ssl/certs/rpm-system.crt -noout -checkend 86400" "SSL certificate valid"
[ $? -ne 0 ] && ((FAILED_CHECKS++))

# NHS compliance checks
echo
echo "🏥 NHS COMPLIANCE CHECKS"
echo "========================="

check_status "test -f /opt/rpm-system/.env" "Environment configuration exists"
[ $? -ne 0 ] && ((FAILED_CHECKS++))

check_status "grep -q 'NHS_CIS2_CLIENT_ID' /opt/rpm-system/.env" "NHS CIS2 configuration present"
[ $? -ne 0 ] && ((FAILED_CHECKS++))

check_status "test -d /opt/rpm-system/logs/audit" "Audit logging directory exists"
[ $? -ne 0 ] && ((FAILED_CHECKS++))

check_status "systemctl is-active auditd --quiet" "System audit daemon running"
[ $? -ne 0 ] && ((FAILED_CHECKS++))

# Performance checks
echo
echo "⚡ PERFORMANCE CHECKS"
echo "====================="

RESPONSE_TIME=$(curl -w "%{time_total}" -s -o /dev/null https://localhost/health)
check_status "echo '$RESPONSE_TIME < 1.0' | bc -l" "Response time < 1 second ($RESPONSE_TIME s)"
[ $? -ne 0 ] && ((FAILED_CHECKS++))

# Security validation
echo
echo "🛡️  SECURITY VALIDATION"
echo "======================="

cd /opt/rpm-system
source venv/bin/activate
python scripts/validate_security.py > /tmp/security_validation.log 2>&1
check_status "grep -q 'PASS' /tmp/security_validation.log" "Security validation passed"
[ $? -ne 0 ] && ((FAILED_CHECKS++))

# Final status
echo
echo "==========================="
if [ $FAILED_CHECKS -eq 0 ]; then
    echo "🎉 ALL CHECKS PASSED - READY FOR GO-LIVE"
    echo "==========================="
    exit 0
else
    echo "❌ $FAILED_CHECKS CHECKS FAILED - NOT READY"
    echo "==========================="
    echo "Please resolve the failed checks before proceeding with go-live."
    exit 1
fi
```

### 2. Go-Live Deployment

```bash
#!/bin/bash
# golive_deployment.sh

echo "=== NHS Remote Patient Monitoring System ==="
echo "=== GO-LIVE DEPLOYMENT ==="
echo

# Check if pre-go-live checklist passed
echo "Running pre-go-live checklist..."
if ! ./pre_golive_checklist.sh; then
    echo "❌ Pre-go-live checklist failed. Aborting deployment."
    exit 1
fi

echo "✅ Pre-go-live checklist passed. Proceeding with deployment..."

# Create deployment timestamp
DEPLOYMENT_TIME=$(date '+%Y-%m-%d_%H-%M-%S')
echo "Deployment started at: $DEPLOYMENT_TIME"

# Enable monitoring
echo "🔍 Enabling enhanced monitoring..."
systemctl start rpm-system-monitor.service

# Enable security monitoring
echo "🛡️  Enabling security monitoring..."
cd /opt/rpm-system
source venv/bin/activate
python -c "
from backend.app.utils.security_monitor import security_monitor
security_monitor.start_monitoring()
print('Security monitoring activated')
"

# Start application
echo "🚀 Starting application services..."
systemctl start rpm-system.service
sleep 10

# Verify all services
echo "✅ Verifying services..."
systemctl is-active --quiet postgresql && echo "✅ PostgreSQL: Active"
systemctl is-active --quiet redis-server && echo "✅ Redis: Active"
systemctl is-active --quiet nginx && echo "✅ Nginx: Active"
systemctl is-active --quiet rpm-system && echo "✅ RPM System: Active"

# Test endpoints
echo "🧪 Testing critical endpoints..."
curl -s https://localhost/health | grep -q "healthy" && echo "✅ Health endpoint: OK"
curl -s https://localhost/api/auth/nhs-cis2/authorize | grep -q "authorize" && echo "✅ NHS CIS2 endpoint: OK"

# Log go-live event
echo "📝 Logging go-live event..."
python -c "
from backend.app import create_app
from backend.app.utils.security import AuditLogger

app = create_app('production')
with app.app_context():
    audit_logger = AuditLogger()
    audit_logger.log_security_event(
        event_type='system_golive',
        details={
            'deployment_time': '$DEPLOYMENT_TIME',
            'version': '1.0',
            'environment': 'production',
            'status': 'success'
        }
    )
    print('Go-live event logged')
"

echo
echo "🎉 GO-LIVE DEPLOYMENT COMPLETED SUCCESSFULLY!"
echo "System is now live and ready for NHS production use."
echo "Deployment time: $DEPLOYMENT_TIME"
echo "Monitor the system at: https://your-domain.nhs.uk"
echo
echo "Next steps:"
echo "1. Monitor system performance for 24 hours"
echo "2. Verify all NHS CIS2 integrations"
echo "3. Conduct user acceptance testing"
echo "4. Schedule post-deployment security review"
```

---

## Post-Deployment Monitoring

### 1. Monitoring Setup

```bash
#!/bin/bash
# monitoring_setup.sh

echo "Setting up post-deployment monitoring..."

# Create monitoring script
sudo tee /opt/rpm-system/scripts/health_monitor.sh << 'EOF'
#!/bin/bash
# Health monitoring script for NHS RPM system

LOG_FILE="/opt/rpm-system/logs/health_monitor.log"
ALERT_EMAIL="admin@yourorg.nhs.uk"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_FILE
}

check_service() {
    if systemctl is-active --quiet $1; then
        log_message "✅ $1 is running"
        return 0
    else
        log_message "❌ $1 is not running"
        return 1
    fi
}

check_endpoint() {
    if curl -s -f $1 > /dev/null; then
        log_message "✅ Endpoint $1 is responding"
        return 0
    else
        log_message "❌ Endpoint $1 is not responding"
        return 1
    fi
}

# Monitor services
FAILED_SERVICES=()

check_service "postgresql" || FAILED_SERVICES+=("postgresql")
check_service "redis-server" || FAILED_SERVICES+=("redis-server")
check_service "nginx" || FAILED_SERVICES+=("nginx")
check_service "rpm-system" || FAILED_SERVICES+=("rpm-system")

# Monitor endpoints
FAILED_ENDPOINTS=()

check_endpoint "https://localhost/health" || FAILED_ENDPOINTS+=("health")
check_endpoint "https://localhost/api/auth/status" || FAILED_ENDPOINTS+=("auth-status")

# Check disk space
DISK_USAGE=$(df /opt/rpm-system | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 80 ]; then
    log_message "⚠️  Disk usage is high: ${DISK_USAGE}%"
fi

# Check memory usage
MEMORY_USAGE=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
if [ $MEMORY_USAGE -gt 80 ]; then
    log_message "⚠️  Memory usage is high: ${MEMORY_USAGE}%"
fi

# Send alerts if needed
if [ ${#FAILED_SERVICES[@]} -gt 0 ] || [ ${#FAILED_ENDPOINTS[@]} -gt 0 ]; then
    ALERT_MESSAGE="NHS RPM System Alert:\n"
    
    if [ ${#FAILED_SERVICES[@]} -gt 0 ]; then
        ALERT_MESSAGE+="\nFailed Services: ${FAILED_SERVICES[*]}"
    fi
    
    if [ ${#FAILED_ENDPOINTS[@]} -gt 0 ]; then
        ALERT_MESSAGE+="\nFailed Endpoints: ${FAILED_ENDPOINTS[*]}"
    fi
    
    echo -e "$ALERT_MESSAGE" | mail -s "NHS RPM System Alert" $ALERT_EMAIL
    log_message "Alert sent to $ALERT_EMAIL"
fi
EOF

chmod +x /opt/rpm-system/scripts/health_monitor.sh

# Create cron job for monitoring
echo "*/5 * * * * /opt/rpm-system/scripts/health_monitor.sh" | crontab -

echo "Health monitoring setup completed"
```

### 2. Performance Monitoring

```bash
#!/bin/bash
# performance_monitoring.sh

# Create performance monitoring script
sudo tee /opt/rpm-system/scripts/performance_monitor.sh << 'EOF'
#!/bin/bash
# Performance monitoring for NHS RPM system

METRICS_FILE="/opt/rpm-system/logs/performance_metrics.log"

# Function to log metrics
log_metric() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'),$1,$2" >> $METRICS_FILE
}

# CPU usage
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
log_metric "cpu_usage" "$CPU_USAGE"

# Memory usage
MEMORY_USAGE=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
log_metric "memory_usage" "$MEMORY_USAGE"

# Disk usage
DISK_USAGE=$(df /opt/rpm-system | awk 'NR==2 {print $5}' | sed 's/%//')
log_metric "disk_usage" "$DISK_USAGE"

# Application response time
RESPONSE_TIME=$(curl -w "%{time_total}" -s -o /dev/null https://localhost/health)
log_metric "response_time" "$RESPONSE_TIME"

# Database connections
DB_CONNECTIONS=$(sudo -u postgres psql -d rpm_db -t -c "SELECT count(*) FROM pg_stat_activity;" | xargs)
log_metric "db_connections" "$DB_CONNECTIONS"

# Redis memory usage
REDIS_MEMORY=$(redis-cli info memory | grep used_memory_human | cut -d: -f2 | tr -d '\r')
log_metric "redis_memory" "$REDIS_MEMORY"

# Active sessions
ACTIVE_SESSIONS=$(redis-cli keys "session:*" | wc -l)
log_metric "active_sessions" "$ACTIVE_SESSIONS"
EOF

chmod +x /opt/rpm-system/scripts/performance_monitor.sh

# Create cron job for performance monitoring
echo "*/1 * * * * /opt/rpm-system/scripts/performance_monitor.sh" | crontab -

echo "Performance monitoring setup completed"
```

---

## Rollback Procedures

### 1. Emergency Rollback

```bash
#!/bin/bash
# emergency_rollback.sh

echo "=== EMERGENCY ROLLBACK PROCEDURE ==="
echo "This will rollback the NHS RPM system to the previous stable version"
read -p "Are you sure you want to proceed? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Rollback cancelled"
    exit 1
fi

ROLLBACK_TIME=$(date '+%Y-%m-%d_%H-%M-%S')
echo "Starting emergency rollback at: $ROLLBACK_TIME"

# Stop current services
echo "Stopping current services..."
systemctl stop rpm-system
systemctl stop nginx

# Backup current version
echo "Backing up current version..."
sudo cp -r /opt/rpm-system /opt/rpm-system-backup-$ROLLBACK_TIME

# Restore from backup
echo "Restoring from backup..."
if [ -d "/opt/rpm-system-backup-last-stable" ]; then
    sudo rm -rf /opt/rpm-system
    sudo cp -r /opt/rpm-system-backup-last-stable /opt/rpm-system
    sudo chown -R rpm-app:rpm-app /opt/rpm-system
else
    echo "❌ No stable backup found!"
    exit 1
fi

# Restore database
echo "Restoring database..."
sudo -u postgres psql << EOF
DROP DATABASE IF EXISTS rpm_db_backup_$ROLLBACK_TIME;
CREATE DATABASE rpm_db_backup_$ROLLBACK_TIME WITH TEMPLATE rpm_db;
DROP DATABASE rpm_db;
CREATE DATABASE rpm_db WITH TEMPLATE rpm_db_last_stable;
EOF

# Restart services
echo "Restarting services..."
systemctl start rpm-system
systemctl start nginx

# Verify rollback
echo "Verifying rollback..."
sleep 10

if curl -s https://localhost/health | grep -q "healthy"; then
    echo "✅ Rollback successful - system is operational"
    
    # Log rollback event
    cd /opt/rpm-system
    source venv/bin/activate
    python -c "
from backend.app import create_app
from backend.app.utils.security import AuditLogger

app = create_app('production')
with app.app_context():
    audit_logger = AuditLogger()
    audit_logger.log_security_event(
        event_type='emergency_rollback',
        details={
            'rollback_time': '$ROLLBACK_TIME',
            'reason': 'emergency_rollback',
            'status': 'success'
        }
    )
    print('Rollback event logged')
"
else
    echo "❌ Rollback failed - manual intervention required"
    exit 1
fi

echo "Emergency rollback completed at: $(date '+%Y-%m-%d_%H-%M-%S')"
```

---

**Document Version**: 1.0  
**Last Updated**: May 28, 2025  
**Next Review**: June 28, 2025  
**Approved By**: NHS Digital Technical Team
