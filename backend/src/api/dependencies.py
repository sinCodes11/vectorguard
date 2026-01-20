"""API dependencies for authentication and authorization."""
import os
from typing import Optional
from fastapi import Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from src.database.connection import get_db
from src.utils.auth import auth_service
from src.models.auth import User


# Check if authentication is required (can be disabled for development)
AUTH_REQUIRED = os.getenv("REQUIRE_AUTH", "false").lower() == "true"


async def get_current_user_optional(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Get current user from JWT token or API key (optional).
    Returns None if no valid authentication provided.
    """
    if not authorization:
        return None
    
    try:
        # Check if it's a Bearer token (JWT)
        if authorization.startswith("Bearer "):
            token = authorization.replace("Bearer ", "")
            payload = auth_service.verify_token(token)
            username = payload.get("sub")
            if username:
                user = db.query(User).filter(User.username == username).first()
                return user
        
        # Check if it's an API key
        elif authorization.startswith("ApiKey "):
            api_key = authorization.replace("ApiKey ", "")
            user = auth_service.verify_api_key(db, api_key)
            return user
        
    except Exception:
        # Invalid token/key, return None for optional auth
        pass
    
    return None


async def get_current_user_required(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> User:
    """
    Get current user from JWT token or API key (required).
    Raises 401 if no valid authentication provided.
    """
    if not AUTH_REQUIRED:
        # If auth is not required, return a mock user for development
        return User(
            id=0,
            username="dev_user",
            email="dev@localhost",
            is_active=True,
            is_superuser=False
        )
    
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = None
    
    try:
        # Check if it's a Bearer token (JWT)
        if authorization.startswith("Bearer "):
            token = authorization.replace("Bearer ", "")
            payload = auth_service.verify_token(token)
            username = payload.get("sub")
            if username:
                user = db.query(User).filter(User.username == username).first()
        
        # Check if it's an API key
        elif authorization.startswith("ApiKey "):
            api_key = authorization.replace("ApiKey ", "")
            user = auth_service.verify_api_key(db, api_key)
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    
    return user


async def get_current_superuser(
    current_user: User = Depends(get_current_user_required)
) -> User:
    """
    Verify that the current user is a superuser.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user

