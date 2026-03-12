from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.models import TokenData, User, UserRole, UserStatus
from app.database import users_db

# Security configuration
SECRET_KEY = "your-super-secret-key-change-in-production-2024"  # Change this in production!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Default 60 minutes (1 hour)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hashed password
    
    Args:
        plain_password: The password entered by user
        hashed_password: The stored hash from database
    
    Returns:
        bool: True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt
    
    Args:
        password: Plain text password
    
    Returns:
        str: Bcrypt hashed password
    """
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str) -> Optional[User]:
    """
    Authenticate a user by username and password
    
    Args:
        username: The username to authenticate
        password: The password to verify
    
    Returns:
        User object if authentication successful, False otherwise
    """
    # Check if user exists
    user = users_db.get(username)
    if not user:
        return None
    
    # Verify password
    if not verify_password(password, user.password_hash):
        return None
    
    # Check if user is active (not pending, not inactive, not rejected)
    if user.status != UserStatus.ACTIVE:
        return None
    
    # Update last login timestamp
    user.last_login = datetime.now()
    
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token
    
    Args:
        data: Dictionary containing user data (sub, user_id, role)
        expires_delta: Optional expiration time override
    
    Returns:
        str: JWT token string
    """
    to_encode = data.copy()
    
    # Set expiration time
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Add expiration to token payload
    to_encode.update({"exp": expire})
    
    # Encode the JWT token
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """
    Get the current user from the JWT token
    
    Args:
        token: JWT token from Authorization header
    
    Returns:
        User object if token is valid
    
    Raises:
        HTTPException 401: If token is invalid or user not found
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: str = payload.get("user_id")
        role: str = payload.get("role")
        
        if username is None or user_id is None:
            raise credentials_exception
        
        token_data = TokenData(username=username, user_id=user_id, role=role)
    except JWTError:
        raise credentials_exception
    
    # Get user from database
    user = users_db.get(username)
    if user is None:
        raise credentials_exception
    
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Get the current active user (users with ACTIVE status only)
    
    Args:
        current_user: User object from get_current_user
    
    Returns:
        User object if user is active
    
    Raises:
        HTTPException 400: If user is not active
    """
    if current_user.status != UserStatus.ACTIVE:
        raise HTTPException(
            status_code=400, 
            detail="User account is not active. Please contact administrator."
        )
    return current_user

async def get_admin_user(current_user: User = Depends(get_current_active_user)) -> User:
    """
    Get the current user if they are an admin or super admin
    
    Args:
        current_user: User object from get_current_active_user
    
    Returns:
        User object if user has admin privileges
    
    Raises:
        HTTPException 403: If user is not an admin
    """
    if current_user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required. You do not have permission to access this resource."
        )
    return current_user

async def get_super_admin(current_user: User = Depends(get_current_active_user)) -> User:
    """
    Get the current user if they are a super admin
    
    Args:
        current_user: User object from get_current_active_user
    
    Returns:
        User object if user is super admin
    
    Raises:
        HTTPException 403: If user is not a super admin
    """
    if current_user.role != UserRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin access required. Only super administrators can access this resource."
        )
    return current_user

def create_admin_token(admin_user: User) -> str:
    """
    Create a token specifically for admin users with extended permissions
    
    Args:
        admin_user: Admin user object
    
    Returns:
        str: JWT token with admin claims
    """
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": admin_user.username, 
            "user_id": admin_user.id, 
            "role": admin_user.role.value,
            "admin_level": "super" if admin_user.role == UserRole.SUPER_ADMIN else "regular"
        },
        expires_delta=access_token_expires
    )
    return access_token

def verify_token(token: str) -> Optional[dict]:
    """
    Verify a JWT token and return its payload
    
    Args:
        token: JWT token string
    
    Returns:
        dict: Token payload if valid, None if invalid
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def refresh_token(token: str) -> Optional[str]:
    """
    Refresh an expired token by creating a new one with extended time
    
    Args:
        token: Expired JWT token
    
    Returns:
        str: New JWT token if valid, None if invalid
    """
    try:
        # Decode without verifying expiration
        payload = jwt.decode(
            token, 
            SECRET_KEY, 
            algorithms=[ALGORITHM], 
            options={"verify_exp": False}
        )
        
        # Remove exp from payload
        payload.pop("exp", None)
        
        # Create new token with fresh expiration
        username = payload.get("sub")
        user = users_db.get(username)
        if not user or user.status != UserStatus.ACTIVE:
            return None
        
        return create_access_token(data=payload)
    except JWTError:
        return None

def change_user_password(user: User, old_password: str, new_password: str) -> bool:
    """
    Change a user's password after verifying old password
    
    Args:
        user: User object
        old_password: Current password for verification
        new_password: New password to set
    
    Returns:
        bool: True if password changed successfully, False if old password incorrect
    """
    if not verify_password(old_password, user.password_hash):
        return False
    
    user.password_hash = get_password_hash(new_password)
    user.updated_at = datetime.now()
    return True

def reset_user_password(user: User, new_password: str, reset_by: str) -> None:
    """
    Reset a user's password (admin function, no old password required)
    
    Args:
        user: User object
        new_password: New password to set
        reset_by: Username of admin performing reset
    """
    user.password_hash = get_password_hash(new_password)
    user.updated_at = datetime.now()
    user.updated_by = reset_by
    # Log this action separately

def get_token_expiration(token: str) -> Optional[datetime]:
    """
    Get the expiration time from a token
    
    Args:
        token: JWT token string
    
    Returns:
        datetime: Expiration time if token valid, None if invalid
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
        exp = payload.get("exp")
        if exp:
            return datetime.fromtimestamp(exp)
        return None
    except JWTError:
        return None

def is_token_expired(token: str) -> bool:
    """
    Check if a token is expired
    
    Args:
        token: JWT token string
    
    Returns:
        bool: True if token expired, False if still valid
    """
    try:
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return False
    except jwt.ExpiredSignatureError:
        return True
    except JWTError:
        return True  # Consider invalid tokens as expired

def get_user_from_token(token: str) -> Optional[User]:
    """
    Get user object from token without requiring authentication dependency
    
    Args:
        token: JWT token string
    
    Returns:
        User object if token valid, None if invalid
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username:
            return users_db.get(username)
        return None
    except JWTError:
        return None