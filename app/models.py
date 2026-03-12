from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime
import uuid
from enum import Enum

class UserRole(str, Enum):
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    REQUESTER = "requester"

class UserStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    INACTIVE = "inactive"
    REJECTED = "rejected"

class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: EmailStr
    password_hash: str
    role: UserRole
    status: UserStatus = UserStatus.PENDING
    full_name: str
    campus: str  # Now a string field for any campus/branch name
    department: str
    employee_id: Optional[str] = None
    position: Optional[str] = None
    contact_number: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)
    created_by: Optional[str] = None
    updated_at: datetime = Field(default_factory=datetime.now)
    updated_by: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    comments: Optional[str] = None

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: str
    campus: str  # Text input for campus
    department: str
    employee_id: Optional[str] = None
    position: Optional[str] = None
    contact_number: Optional[str] = None

class AdminCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: str
    campus: str  # Text input for campus
    department: str
    employee_id: str
    position: str
    contact_number: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    campus: Optional[str] = None  # Can update campus text
    department: Optional[str] = None
    position: Optional[str] = None
    contact_number: Optional[str] = None
    status: Optional[UserStatus] = None

class UserApproval(BaseModel):
    user_id: str
    approved: bool
    comments: Optional[str] = None
    role: Optional[UserRole] = None

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    user_id: str
    username: str
    full_name: str
    campus: str

class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[str] = None
    role: Optional[str] = None

class PasswordChange(BaseModel):
    old_password: str
    new_password: str

class RequestStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    IN_REVIEW = "in_review"
    PROCESSING = "processing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"

class BudgetCategory(str, Enum):
    MARKETING = "marketing"
    SALARY = "salary"
    EQUIPMENT = "equipment"
    TRAVEL = "travel"
    TRAINING = "training"
    OPERATIONS = "operations"
    MAINTENANCE = "maintenance"
    OTHER = "other"

class BudgetRequest(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    amount: float = Field(gt=0)
    category: BudgetCategory
    requester_id: str
    requester_name: str
    requester_email: str
    campus: str  # Will be copied from user's campus
    department: str
    purpose: Optional[str] = None
    expected_benefits: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    status: RequestStatus = RequestStatus.PENDING
    progress: int = Field(ge=0, le=100, default=0)
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    comments: Optional[str] = None
    admin_notes: Optional[str] = None
    rejection_reason: Optional[str] = None

class BudgetRequestCreate(BaseModel):
    title: str
    description: str
    amount: float
    category: BudgetCategory
    purpose: Optional[str] = None
    expected_benefits: Optional[str] = None

class BudgetRequestUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    amount: Optional[float] = Field(None, gt=0)
    category: Optional[BudgetCategory] = None
    purpose: Optional[str] = None
    expected_benefits: Optional[str] = None

class BudgetRequestReview(BaseModel):
    status: RequestStatus
    comments: Optional[str] = None
    admin_notes: Optional[str] = None
    rejection_reason: Optional[str] = None

class ActivityLog(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    username: str
    action: str
    details: str
    timestamp: datetime = Field(default_factory=datetime.now)
    ip_address: Optional[str] = None