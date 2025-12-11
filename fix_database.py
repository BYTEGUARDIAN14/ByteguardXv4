#!/usr/bin/env python3
"""
Fix database schema issues
"""

import sqlite3

def fix_database():
    """Fix database schema"""
    print("🔧 Fixing database schema...")
    
    conn = sqlite3.connect('byteguardx.db')
    cursor = conn.cursor()
    
    # Check current schema
    cursor.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]
    print(f"Current columns: {columns}")
    
    # Add missing columns if needed
    missing_columns = []
    
    if 'scans_this_month' not in columns:
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN scans_this_month INTEGER DEFAULT 0")
            missing_columns.append('scans_this_month')
        except sqlite3.OperationalError:
            pass  # Column already exists
    
    if 'total_scans' not in columns:
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN total_scans INTEGER DEFAULT 0")
            missing_columns.append('total_scans')
        except sqlite3.OperationalError:
            pass  # Column already exists
    
    conn.commit()
    
    # Verify fix
    cursor.execute("PRAGMA table_info(users)")
    new_columns = [row[1] for row in cursor.fetchall()]
    print(f"Updated columns: {new_columns}")
    
    # Test query
    cursor.execute("SELECT id, email, username, role, scans_this_month, total_scans FROM users")
    users = cursor.fetchall()
    print(f"Users in database: {len(users)}")
    
    for user in users:
        print(f"  - {user[2]} ({user[1]}) - Role: {user[3]}")
    
    conn.close()
    
    if missing_columns:
        print(f"✅ Added missing columns: {missing_columns}")
    else:
        print("✅ Database schema is correct")

if __name__ == "__main__":
    fix_database()
