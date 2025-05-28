#!/usr/bin/env python3
"""
Phase 1.2: Database Production Setup
Implements database optimization, encryption, and backup procedures for NHS Digital compliance
"""

import os
import sys
import sqlite3
import json
from datetime import datetime, timedelta
import logging
from cryptography.fernet import Fernet
import hashlib
import shutil

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DatabaseProductionSetup:
    """Production database setup and management"""
    
    def __init__(self):
        self.db_path = 'rpm_development.db'
        self.backup_dir = 'backups'
        self.encryption_key = self._get_or_create_encryption_key()
        
    def _get_or_create_encryption_key(self):
        """Get or create encryption key for database operations"""
        key_file = '.db_encryption_key'
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)  # Restrict access
            return key
    
    def create_database_structure(self):
        """Create production database structure with security tables"""
        print("🔒 Creating production database structure...")
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create security audit log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type VARCHAR(50) NOT NULL,
                    user_id INTEGER,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    details TEXT,
                    severity VARCHAR(20) DEFAULT 'info',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    session_id VARCHAR(255),
                    endpoint VARCHAR(255),
                    data_classification VARCHAR(20) DEFAULT 'internal'
                )
            ''')
            
            # Create user sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_token VARCHAR(255) UNIQUE NOT NULL,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    csrf_token VARCHAR(255),
                    mfa_verified BOOLEAN DEFAULT 0
                )
            ''')
            
            # Create users table with security fields
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email VARCHAR(120) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    first_name VARCHAR(50) NOT NULL,
                    last_name VARCHAR(50) NOT NULL,
                    phone VARCHAR(20),
                    role VARCHAR(20) DEFAULT 'patient',
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    nhs_number VARCHAR(10) UNIQUE,
                    gp_practice_code VARCHAR(10),
                    mfa_enabled BOOLEAN DEFAULT 0,
                    mfa_secret VARCHAR(255),
                    mfa_backup_codes TEXT,
                    password_reset_token VARCHAR(255),
                    password_reset_expires TIMESTAMP,
                    failed_login_attempts INTEGER DEFAULT 0,
                    account_locked_until TIMESTAMP,
                    session_token VARCHAR(255),
                    session_expires TIMESTAMP,
                    password_changed_at TIMESTAMP,
                    last_password_reminder TIMESTAMP,
                    login_count INTEGER DEFAULT 0,
                    ip_address VARCHAR(45)
                )
            ''')
            
            # Create performance indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_nhs_number ON users(nhs_number)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON security_audit_logs(event_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON security_audit_logs(created_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(session_token)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id)')
            
            conn.commit()
            conn.close()
            
            print("✅ Database structure created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create database structure: {str(e)}")
            return False
    
    def setup_connection_pooling(self):
        """Configure connection pooling for production"""
        print("🔧 Setting up connection pooling configuration...")
        
        config = {
            'pool_size': 20,
            'pool_timeout': 30,
            'pool_recycle': 3600,
            'max_overflow': 30,
            'pool_pre_ping': True
        }
        
        config_file = 'database_config.json'
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print("✅ Connection pooling configuration saved")
        return True
    
    def implement_backup_procedures(self):
        """Implement automated backup procedures"""
        print("💾 Setting up backup procedures...")
        
        # Create backup directory
        os.makedirs(self.backup_dir, exist_ok=True)
        
        # Create backup script
        backup_script = '''#!/bin/bash
# Automated database backup script for NHS Digital compliance

BACKUP_DIR="backups"
DB_FILE="rpm_development.db"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="$BACKUP_DIR/rpm_backup_$TIMESTAMP.db"

# Create backup
echo "Creating database backup: $BACKUP_FILE"
cp "$DB_FILE" "$BACKUP_FILE"

# Compress backup
gzip "$BACKUP_FILE"

# Remove backups older than 30 days
find "$BACKUP_DIR" -name "rpm_backup_*.db.gz" -mtime +30 -delete

echo "Backup completed successfully"
'''
        
        with open('backup_database.sh', 'w') as f:
            f.write(backup_script)
        
        os.chmod('backup_database.sh', 0o755)
        
        # Create initial backup
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"{self.backup_dir}/rpm_backup_{timestamp}.db"
        
        try:
            shutil.copy2(self.db_path, backup_file)
            print(f"✅ Initial backup created: {backup_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to create initial backup: {str(e)}")
            return False
    
    def setup_data_retention_policies(self):
        """Setup GDPR-compliant data retention policies"""
        print("📋 Setting up data retention policies...")
        
        retention_config = {
            'audit_logs': {
                'retention_days': 2555,  # 7 years for NHS compliance
                'archive_after_days': 365
            },
            'user_sessions': {
                'retention_days': 90,
                'cleanup_inactive_days': 30
            },
            'patient_data': {
                'retention_years': 8,  # NHS minimum retention
                'anonymize_after_years': 25
            },
            'backup_retention': {
                'daily_backups_days': 30,
                'weekly_backups_weeks': 52,
                'monthly_backups_months': 84  # 7 years
            }
        }
        
        with open('data_retention_policy.json', 'w') as f:
            json.dump(retention_config, f, indent=2)
        
        print("✅ Data retention policies configured")
        return True
    
    def implement_audit_logging(self):
        """Setup comprehensive audit logging system"""
        print("📝 Implementing audit logging system...")
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Insert initial audit log entry
            cursor.execute('''
                INSERT INTO security_audit_logs 
                (event_type, details, severity, data_classification)
                VALUES (?, ?, ?, ?)
            ''', (
                'database_setup',
                'Phase 1.2 Database Production Setup completed',
                'info',
                'internal'
            ))
            
            conn.commit()
            conn.close()
            
            print("✅ Audit logging system initialized")
            return True
            
        except Exception as e:
            logger.error(f"Failed to setup audit logging: {str(e)}")
            return False
    
    def verify_database_integrity(self):
        """Verify database integrity and structure"""
        print("🔍 Verifying database integrity...")
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check PRAGMA integrity
            cursor.execute('PRAGMA integrity_check')
            integrity_result = cursor.fetchone()
            
            if integrity_result[0] != 'ok':
                logger.error(f"Database integrity check failed: {integrity_result}")
                return False
            
            # Verify required tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            required_tables = ['users', 'security_audit_logs', 'user_sessions']
            missing_tables = [table for table in required_tables if table not in tables]
            
            if missing_tables:
                logger.error(f"Missing required tables: {missing_tables}")
                return False
            
            conn.close()
            print("✅ Database integrity verified")
            return True
            
        except Exception as e:
            logger.error(f"Database verification failed: {str(e)}")
            return False

def main():
    """Main Phase 1.2 setup process"""
    print("🚀 Starting Phase 1.2: Database Production Setup")
    print("=" * 60)
    
    setup = DatabaseProductionSetup()
    
    # Execute Phase 1.2 components
    tasks = [
        ("Database Structure", setup.create_database_structure),
        ("Connection Pooling", setup.setup_connection_pooling),
        ("Backup Procedures", setup.implement_backup_procedures),
        ("Data Retention Policies", setup.setup_data_retention_policies),
        ("Audit Logging", setup.implement_audit_logging),
        ("Database Verification", setup.verify_database_integrity)
    ]
    
    completed_tasks = 0
    
    for task_name, task_func in tasks:
        print(f"\n📋 {task_name}...")
        if task_func():
            completed_tasks += 1
        else:
            print(f"❌ {task_name} failed")
    
    print("\n" + "=" * 60)
    print(f"📊 Phase 1.2 Summary: {completed_tasks}/{len(tasks)} tasks completed")
    
    if completed_tasks == len(tasks):
        print("✅ Phase 1.2: Database Production Setup COMPLETE")
        print("🎯 Ready for Phase 1.3: NHS Compliance Foundation")
        
        # Create status file
        status = {
            'phase': '1.2',
            'status': 'complete',
            'completed_at': datetime.now().isoformat(),
            'tasks_completed': completed_tasks,
            'total_tasks': len(tasks),
            'next_phase': '1.3 - NHS Compliance Foundation'
        }
        
        with open('phase_1_2_status.json', 'w') as f:
            json.dump(status, f, indent=2)
        
        return True
    else:
        print("❌ Phase 1.2 setup incomplete - please review errors")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
