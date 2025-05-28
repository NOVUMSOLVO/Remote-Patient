#!/bin/bash
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
