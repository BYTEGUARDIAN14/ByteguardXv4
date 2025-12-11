
from sqlalchemy import create_engine, inspect
import sys
import os

db_url = 'sqlite:///byteguardx_v2.db'
if not os.path.exists('byteguardx_v2.db'):
    print("byteguardx_v2.db does not exist!")
    
engine = create_engine(db_url)
inspector = inspect(engine)

try:
    tables = inspector.get_table_names()
    print(f"Tables: {tables}")
    
    if 'users' in tables:
        columns = [c['name'] for c in inspector.get_columns('users')]
        print(f"Users columns: {columns}")
        
        expected = ['is_active', 'email_verified', 'created_at', 'first_name', 'last_name']
        missing = [c for c in expected if c not in columns]
        if missing:
            print(f"MISSING COLUMNS: {missing}")
        else:
            print("All expected columns present.")
    else:
        print("Users table missing!")
        
except Exception as e:
    print(f"Error inspecting DB: {e}")
