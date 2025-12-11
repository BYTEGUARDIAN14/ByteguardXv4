from sqlalchemy import create_engine, inspect
import os

db_path = os.path.abspath('byteguardx_v3.db')
print(f"Checking database: {db_path}")
print(f"Exists: {os.path.exists(db_path)}")

if os.path.exists(db_path):
    engine = create_engine(f'sqlite:///{db_path}')
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    print(f"Tables: {tables}")
    
    if 'users' in tables:
        columns = [c['name'] for c in inspector.get_columns('users')]
        print(f"User columns: {columns}")
        
        expected = ['id', 'email', 'username', 'password_hash', 'first_name', 'last_name', 'role', 'is_active', 'email_verified', 'created_at']
        missing = [c for c in expected if c not in columns]
        if missing:
            print(f"MISSING COLUMNS: {missing}")
        else:
            print("All expected columns present!")
    else:
        print("users table NOT FOUND!")
