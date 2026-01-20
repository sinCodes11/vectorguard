"""Authentication routes."""
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import List, Optional

from src.database.connection import get_db
from src.utils.auth import auth_service, ACCESS_TOKEN_EXPIRE_MINUTES
from src.models.auth import User
from src.api.dependencies import get_current_user_required, get_current_superuser


router = APIRouter(prefix="/auth", tags=["authentication"])


class Token(BaseModel):
    access_token: str
    token_type: str


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str]
    is_active: bool
    is_superuser: bool
    
    class Config:
        from_attributes = True


class APIKeyCreate(BaseModel):
    key_name: str
    permissions: Optional[List[str]] = None
    expires_days: Optional[int] = None


class APIKeyResponse(BaseModel):
    api_key: str
    key_prefix: str
    key_name: str
    message: str


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Login with username and password to get JWT token."""
    user = auth_service.authenticate_user(db, form_data.username, form_data.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth_service.create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/register", response_model=UserResponse)
async def register(
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    """Register a new user (public endpoint for initial setup)."""
    # Check if this is the first user (make them superuser)
    user_count = db.query(User).count()
    is_first_user = user_count == 0
    
    user = auth_service.create_user(
        db=db,
        username=user_data.username,
        email=user_data.email,
        password=user_data.password,
        full_name=user_data.full_name,
        is_superuser=is_first_user
    )
    
    return user


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user_required)
):
    """Get current user information."""
    return current_user


@router.post("/api-keys", response_model=APIKeyResponse)
async def create_api_key(
    key_data: APIKeyCreate,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db)
):
    """Create a new API key for the current user."""
    result = auth_service.create_api_key(
        db=db,
        user_id=current_user.id,
        key_name=key_data.key_name,
        permissions=key_data.permissions,
        expires_days=key_data.expires_days
    )
    
    return {
        "api_key": result["api_key"],
        "key_prefix": result["key_prefix"],
        "key_name": key_data.key_name,
        "message": "Save this API key securely. It will not be shown again."
    }


@router.get("/api-keys")
async def list_api_keys(
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db)
):
    """List all API keys for the current user."""
    keys = auth_service.list_user_api_keys(db, current_user.id)
    return keys


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: int,
    current_user: User = Depends(get_current_user_required),
    db: Session = Depends(get_db)
):
    """Revoke an API key."""
    success = auth_service.revoke_api_key(db, key_id, current_user.id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    return {"message": "API key revoked successfully"}

