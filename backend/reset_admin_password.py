#!/usr/bin/env python3
"""
Reset Admin Password Script
This script resets the admin user's password to a new random password.
"""

import os
import sys
import secrets

# Set up the path to import from main.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from main import User, get_password_hash, DATABASE_URL

def reset_admin_password():
    """Reset the admin user's password"""

    # Create database connection
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()

    try:
        # Find an admin user - usernames are user-chosen since the first-run
        # setup flow, so match on the admin flag rather than the name "admin"
        admin = db.query(User).filter(User.is_admin == True).order_by(User.id).first()

        if not admin:
            print("❌ No admin user found in database.")
            print("💡 On a fresh database, open the web UI to create the admin")
            print("   account via the first-run setup screen.")
            return False

        # Generate new random password
        new_password = secrets.token_urlsafe(16)

        # Update admin password
        admin.hashed_password = get_password_hash(new_password)
        db.commit()

        print("=" * 80)
        print("✅ Admin password has been reset!")
        print("")
        print(f"Username: {admin.username}")
        print(f"Password: {new_password}")
        print("")
        print("SAVE THIS PASSWORD - It will not be shown again!")
        print("Change it immediately after login in Settings.")
        print("=" * 80)

        return True

    except Exception as e:
        print(f"❌ Error resetting password: {e}")
        db.rollback()
        return False
    finally:
        db.close()

if __name__ == "__main__":
    # Check if SECRET_KEY is set
    if not os.getenv("SECRET_KEY"):
        print("❌ ERROR: SECRET_KEY environment variable is not set!")
        print("")
        print("Please set SECRET_KEY in your .env file first.")
        print("Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\"")
        sys.exit(1)

    reset_admin_password()
