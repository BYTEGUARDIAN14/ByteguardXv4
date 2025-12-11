
import sys
import os
import logging
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.getcwd())

# Configure logging
logging.basicConfig(level=logging.ERROR)

try:
    print("1. Importing models...")
    from byteguardx.database.models import User, Base
    print("   Models imported.")

    print("2. Checking bcrypt...")
    import bcrypt
    print("   bcrypt imported successfully.")

    print("3. Creating User object...")
    user = User(
        email="test@example.com",
        username="testuser",
        is_active=True,
        email_verified=False,
        created_at=datetime.now()
    )
    print("   User object created.")

    print("4. Setting password...")
    user.set_password("SecurePass1!")
    print("   Password set successfully.")

    print("5. Verifying password...")
    if user.check_password("SecurePass1!"):
        print("   Password verification passed.")
    else:
        print("   Password verification failed.")

    print("6. Saving to Database...")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine('sqlite:///byteguardx_dev.db')
    Session = sessionmaker(bind=engine)
    session = Session()
    
    # Check if exists (cleanup from prev runs)
    existing = session.query(User).filter_by(email="test@example.com").first()
    if existing:
        session.delete(existing)
        session.commit()
        
    session.add(user)
    session.commit()
    print("   User saved to database successfully.")

    print("7. Testing Audit Logger...")
    from byteguardx.security.audit_logger import audit_logger, SecurityEvent, SecurityEventType, EventSeverity
    event = SecurityEvent(
        event_id=None,
        event_type=SecurityEventType.USER_CREATED,
        severity=EventSeverity.LOW,
        timestamp=datetime.now(),
        user_id=str(user.id),
        username="testuser",
        ip_address="127.0.0.1",
        action="register",
        result="success",
        details={'email': "test@example.com"}
    )
    audit_logger.log_event(event)
    print("   Audit event logged.")

    print("SUCCESS: No errors detected anywhere.")

except ImportError as e:
    print(f"IMPORT ERROR: {e}")
except Exception as e:
    print(f"RUNTIME ERROR: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
