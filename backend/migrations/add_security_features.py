"""
Database Migration Script for Security Features
Adds MFA, session management, and audit logging capabilities
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app, db
from app.models import User, SecurityAuditLog, UserSession, DataEncryption

def run_migration():
    """Run the security features migration"""
    app = create_app()
    
    with app.app_context():
        try:
            print("Starting security features migration...")
            
            # Create new tables
            print("Creating new security tables...")
            db.create_all()
            
            # Add new columns to existing User table
            print("Adding security columns to users table...")
            
            # Check if columns already exist to avoid errors
            inspector = db.inspect(db.engine)
            existing_columns = [col['name'] for col in inspector.get_columns('users')]
            
            security_columns = [
                ('mfa_enabled', 'BOOLEAN DEFAULT FALSE'),
                ('mfa_secret', 'VARCHAR(255)'),
                ('mfa_backup_codes', 'TEXT'),
                ('password_reset_token', 'VARCHAR(255)'),
                ('password_reset_expires', 'DATETIME'),
                ('failed_login_attempts', 'INTEGER DEFAULT 0'),
                ('account_locked_until', 'DATETIME'),
                ('session_token', 'VARCHAR(255)'),
                ('session_expires', 'DATETIME'),
                ('password_changed_at', 'DATETIME'),
                ('last_password_reminder', 'DATETIME'),
                ('login_count', 'INTEGER DEFAULT 0'),
                ('ip_address', 'VARCHAR(45)')
            ]
            
            for column_name, column_definition in security_columns:
                if column_name not in existing_columns:
                    try:
                        db.engine.execute(f'ALTER TABLE users ADD COLUMN {column_name} {column_definition}')
                        print(f"Added column: {column_name}")
                    except Exception as e:
                        print(f"Warning: Could not add column {column_name}: {e}")
                else:
                    print(f"Column {column_name} already exists, skipping...")
            
            # Commit changes
            db.session.commit()
            print("Security features migration completed successfully!")
            
            # Initialize security audit log
            try:
                audit_log = SecurityAuditLog(
                    event_type='system_migration',
                    event_status='success',
                    details={
                        'migration': 'security_features',
                        'description': 'Added MFA, session management, and audit logging'
                    }
                )
                db.session.add(audit_log)
                db.session.commit()
                print("Initial audit log entry created.")
            except Exception as e:
                print(f"Could not create initial audit log: {e}")
                
        except Exception as e:
            print(f"Migration failed: {e}")
            db.session.rollback()
            return False
            
    return True

def rollback_migration():
    """Rollback the security features migration"""
    app = create_app()
    
    with app.app_context():
        try:
            print("Starting security features rollback...")
            
            # Drop new tables
            print("Dropping security tables...")
            SecurityAuditLog.__table__.drop(db.engine, checkfirst=True)
            UserSession.__table__.drop(db.engine, checkfirst=True)
            DataEncryption.__table__.drop(db.engine, checkfirst=True)
            
            # Remove columns from User table
            print("Removing security columns from users table...")
            security_columns = [
                'mfa_enabled', 'mfa_secret', 'mfa_backup_codes',
                'password_reset_token', 'password_reset_expires',
                'failed_login_attempts', 'account_locked_until',
                'session_token', 'session_expires',
                'password_changed_at', 'last_password_reminder',
                'login_count', 'ip_address'
            ]
            
            for column_name in security_columns:
                try:
                    db.engine.execute(f'ALTER TABLE users DROP COLUMN {column_name}')
                    print(f"Removed column: {column_name}")
                except Exception as e:
                    print(f"Warning: Could not remove column {column_name}: {e}")
            
            db.session.commit()
            print("Security features rollback completed successfully!")
            
        except Exception as e:
            print(f"Rollback failed: {e}")
            db.session.rollback()
            return False
            
    return True

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'rollback':
        rollback_migration()
    else:
        run_migration()
