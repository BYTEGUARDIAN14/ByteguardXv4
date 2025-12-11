"""Minimal test to debug User model and DB mismatch"""
import os
import sys
sys.path.insert(0, '.')

# Set up database URL
os.environ['DATABASE_URL'] = f'sqlite:///{os.path.abspath("byteguardx_v3.db")}'

from sqlalchemy import create_engine, inspect, text
from byteguardx.database.models import Base, User

# Create engine
engine = create_engine(os.environ['DATABASE_URL'], echo=True)

# Print what SQLAlchemy thinks the User columns are
print("\n=== SQLAlchemy User Model Columns ===")
for col in User.__table__.columns:
    print(f"  - {col.name}: {col.type}")

# Print what's actually in the database
print("\n=== Actual Database Columns ===")
inspector = inspect(engine)
for col in inspector.get_columns('users'):
    print(f"  - {col['name']}: {col['type']}")

# Try a simple query
print("\n=== Testing Query ===")
from sqlalchemy.orm import Session
session = Session(engine)
try:
    # Just try to get the first user or None
    result = session.execute(text("SELECT id, email, username FROM users LIMIT 1")).fetchone()
    print(f"Raw SQL works: {result}")
    
    # Now try ORM query
    user = session.query(User).first()
    print(f"ORM query works: {user}")
except Exception as e:
    print(f"Error: {e}")
finally:
    session.close()
