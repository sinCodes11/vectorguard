from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import secrets
import hashlib
import json
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from src.models.auth import User, APIKey, UserSession
from src.database.connection import get_db
import os

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
API_KEY_LENGTH = 32

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthService:
    def __init__(self):
        self.secret_key = SECRET_KEY
        self.algorithm = ALGORITHM
        self.access_token_expire_minutes = ACCESS_TOKEN_EXPIRE_MINUTES
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Generate password hash."""
        return pwd_context.hash(password)
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token."""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify JWT token and return payload."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    def authenticate_user(self, db: Session, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password."""
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return None
        if not self.verify_password(password, user.hashed_password):
            return None
        return user
    
    def create_user(self, db: Session, username: str, email: str, password: str, 
                   full_name: Optional[str] = None, is_superuser: bool = False) -> User:
        """Create a new user."""
        # Check if user already exists
        if db.query(User).filter(User.username == username).first():
            raise HTTPException(status_code=400, detail="Username already registered")
        
        if db.query(User).filter(User.email == email).first():
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create user
        hashed_password = self.get_password_hash(password)
        user = User(
            username=username,
            email=email,
            hashed_password=hashed_password,
            full_name=full_name,
            is_superuser=is_superuser
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    
    def create_user_session(self, db: Session, user_id: int, user_agent: Optional[str] = None,
                           ip_address: Optional[str] = None) -> str:
        """Create a user session."""
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(days=7)  # 7 days session
        
        user_session = UserSession(
            user_id=user_id,
            session_token=session_token,
            expires_at=expires_at,
            user_agent=user_agent,
            ip_address=ip_address
        )
        db.add(user_session)
        db.commit()
        db.refresh(user_session)
        
        return session_token
    
    def verify_session(self, db: Session, session_token: str) -> Optional[User]:
        """Verify user session and return user."""
        user_session = db.query(UserSession).filter(
            UserSession.session_token == session_token,
            UserSession.expires_at > datetime.utcnow()
        ).first()
        
        if not user_session:
            return None
        
        # Update last accessed
        user_session.last_accessed = datetime.utcnow()
        db.commit()
        
        user = db.query(User).filter(User.id == user_session.user_id, User.is_active == True).first()
        return user
    
    def revoke_session(self, db: Session, session_token: str) -> bool:
        """Revoke a user session."""
        user_session = db.query(UserSession).filter(
            UserSession.session_token == session_token
        ).first()
        
        if user_session:
            db.delete(user_session)
            db.commit()
            return True
        
        return False
    
    def create_api_key(self, db: Session, user_id: int, key_name: str,
                      permissions: List[str] = None, expires_days: Optional[int] = None) -> Dict[str, str]:
        """Create a new API key for user."""
        # Generate API key
        api_key = secrets.token_urlsafe(API_KEY_LENGTH)
        key_prefix = api_key[:8]
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        expires_at = None
        if expires_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_days)
        
        permissions_json = json.dumps(permissions or [])
        
        api_key_obj = APIKey(
            user_id=user_id,
            key_name=key_name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            permissions=permissions_json,
            expires_at=expires_at
        )
        
        db.add(api_key_obj)
        db.commit()
        db.refresh(api_key_obj)
        
        return {
            "api_key": api_key,
            "key_prefix": key_prefix,
            "key_id": str(api_key_obj.id),
            "expires_at": expires_at.isoformat() if expires_at else None
        }
    
    def verify_api_key(self, db: Session, api_key: str) -> Optional[User]:
        """Verify API key and return user."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        api_key_obj = db.query(APIKey).filter(
            APIKey.key_hash == key_hash,
            APIKey.is_active == True
        ).first()
        
        if not api_key_obj:
            return None
        
        # Check expiration
        if api_key_obj.expires_at and api_key_obj.expires_at < datetime.utcnow():
            return None
        
        # Update last used
        api_key_obj.last_used = datetime.utcnow()
        db.commit()
        
        user = db.query(User).filter(User.id == api_key_obj.user_id, User.is_active == True).first()
        return user
    
    def get_api_key_permissions(self, db: Session, api_key: str) -> List[str]:
        """Get permissions for API key."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        api_key_obj = db.query(APIKey).filter(
            APIKey.key_hash == key_hash,
            APIKey.is_active == True
        ).first()
        
        if not api_key_obj:
            return []
        
        try:
            permissions = json.loads(api_key_obj.permissions or "[]")
            return permissions
        except json.JSONDecodeError:
            return []
    
    def revoke_api_key(self, db: Session, key_id: int, user_id: int) -> bool:
        """Revoke an API key."""
        api_key_obj = db.query(APIKey).filter(
            APIKey.id == key_id,
            APIKey.user_id == user_id
        ).first()
        
        if api_key_obj:
            api_key_obj.is_active = False
            db.commit()
            return True
        
        return False
    
    def get_user_api_keys(self, db: Session, user_id: int) -> List[APIKey]:
        """Get all API keys for a user."""
        return db.query(APIKey).filter(APIKey.user_id == user_id).all()

    def list_user_api_keys(self, db: Session, user_id: int) -> List[Dict[str, Any]]:
        """List all API keys for a user (without sensitive data)."""
        api_keys = db.query(APIKey).filter(APIKey.user_id == user_id).all()
        return [
            {
                "id": key.id,
                "key_name": key.key_name,
                "key_prefix": key.key_prefix,
                "is_active": key.is_active,
                "created_at": key.created_at.isoformat() if key.created_at else None,
                "expires_at": key.expires_at.isoformat() if key.expires_at else None,
                "last_used": key.last_used.isoformat() if key.last_used else None
            }
            for key in api_keys
        ]


# Global auth service instance
auth_service = AuthService()


def get_current_user(db: Session = Depends(get_db), token: str = None) -> User:
    """Get current user from JWT token."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    payload = auth_service.verify_token(token)
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return user


def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Get current active user."""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def get_current_superuser(current_user: User = Depends(get_current_active_user)) -> User:
    """Get current superuser."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user