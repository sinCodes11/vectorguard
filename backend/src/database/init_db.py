"""Database initialization script."""
import logging
from sqlalchemy import text
from src.database.connection import engine, SessionLocal, init_db
from src.models.database import Base
from src.utils.auth import auth_service

logger = logging.getLogger(__name__)


def create_tables():
    """Create all database tables."""
    try:
        logger.info("Creating database tables...")
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
        return True
    except Exception as e:
        logger.error(f"Error creating tables: {e}")
        return False


def create_default_user():
    """Create a default admin user if none exists."""
    db = SessionLocal()
    try:
        # Check if any users exist
        from src.models.auth import User
        user_count = db.query(User).count()
        
        if user_count == 0:
            logger.info("Creating default admin user...")
            # Create default admin user
            admin_user = auth_service.create_user(
                db=db,
                username="admin",
                email="admin@vectorguard.local",
                password="changeme123",  # User should change this immediately
                full_name="Administrator",
                is_superuser=True
            )
            logger.info(f"Default admin user created: {admin_user.username}")
            logger.warning("⚠️  Default password is 'changeme123' - CHANGE THIS IMMEDIATELY!")
        else:
            logger.info(f"Users already exist ({user_count} users found)")
        
        return True
    except Exception as e:
        logger.error(f"Error creating default user: {e}")
        return False
    finally:
        db.close()


def verify_database_connection():
    """Verify database connection is working."""
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        logger.info("Database connection verified")
        return True
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return False


def initialize_database():
    """Main initialization function."""
    logger.info("Starting database initialization...")
    
    # Verify connection
    if not verify_database_connection():
        logger.error("Cannot connect to database. Please check your DATABASE_URL")
        return False
    
    # Create tables
    if not create_tables():
        logger.error("Failed to create database tables")
        return False
    
    # Create default user
    if not create_default_user():
        logger.warning("Failed to create default user (may already exist)")
    
    logger.info("Database initialization complete!")
    return True


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    initialize_database()

