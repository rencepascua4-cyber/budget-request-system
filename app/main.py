from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from datetime import timedelta, datetime
from typing import List
import logging

from app.models import *
from app.database import users_db, budget_requests_db, activity_logs_db, SUPER_ADMIN, SAMPLE_ADMIN
from app.auth import (
    authenticate_user, create_access_token, get_password_hash,
    get_current_active_user, get_admin_user, get_super_admin,
    ACCESS_TOKEN_EXPIRE_MINUTES, change_user_password
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ====== CREATE FASTAPI APP ======
app = FastAPI(title="Budget Request System", version="2.0.0")

# ====== MOUNT STATIC FILES ======
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# ====== CORS MIDDLEWARE ======
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ====== STARTUP EVENT ======
@app.on_event("startup")
async def startup_event():
    # Create super admin if not exists
    if "superadmin" not in users_db:
        super_admin = User(
            username=SUPER_ADMIN["username"],
            email=SUPER_ADMIN["email"],
            password_hash=get_password_hash(SUPER_ADMIN["password"]),
            role=UserRole.SUPER_ADMIN,
            status=UserStatus.ACTIVE,
            full_name=SUPER_ADMIN["full_name"],
            campus=SUPER_ADMIN["campus"],
            department=SUPER_ADMIN["department"],
            employee_id=SUPER_ADMIN["employee_id"],
            position=SUPER_ADMIN["position"],
            contact_number=SUPER_ADMIN["contact_number"],
            created_at=datetime.now(),
            approved_at=datetime.now()
        )
        users_db[super_admin.username] = super_admin
        logger.info("Super admin user created")
    
    # Create regular admin if not exists
    if "admin" not in users_db:
        admin_user = User(
            username=SAMPLE_ADMIN["username"],
            email=SAMPLE_ADMIN["email"],
            password_hash=get_password_hash(SAMPLE_ADMIN["password"]),
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
            full_name=SAMPLE_ADMIN["full_name"],
            campus=SAMPLE_ADMIN["campus"],
            department=SAMPLE_ADMIN["department"],
            employee_id=SAMPLE_ADMIN["employee_id"],
            position=SAMPLE_ADMIN["position"],
            contact_number=SAMPLE_ADMIN["contact_number"],
            created_at=datetime.now(),
            created_by="superadmin",
            approved_at=datetime.now(),
            approved_by="superadmin"
        )
        users_db[admin_user.username] = admin_user
        logger.info("Sample admin user created")

# ====== ROOT ENDPOINT ======
@app.get("/")
async def root():
    return {
        "message": "Budget Request System API",
        "version": "2.0.0",
        "status": "running"
    }

# ====== AUTHENTICATION ENDPOINTS ======

@app.post("/token", response_model=Token)
async def login(user_login: UserLogin, request: Request):
    """Login and get access token"""
    user = authenticate_user(user_login.username, user_login.password)
    if not user:
        logger.warning(f"Failed login attempt for username: {user_login.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password or account not active",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "user_id": user.id, "role": user.role.value},
        expires_delta=access_token_expires
    )
    
    logger.info(f"User {user.username} logged in successfully")
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        role=user.role.value,
        user_id=user.id,
        username=user.username,
        full_name=user.full_name,
        campus=user.campus
    )

@app.post("/register", response_model=User)
async def register(user_data: UserCreate, request: Request):
    """Register a new requester account"""
    if user_data.username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    for user in users_db.values():
        if user.email == user_data.email:
            raise HTTPException(status_code=400, detail="Email already exists")
        if user_data.employee_id and user.employee_id == user_data.employee_id:
            raise HTTPException(status_code=400, detail="Employee ID already exists")
    
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=get_password_hash(user_data.password),
        role=UserRole.REQUESTER,
        status=UserStatus.PENDING,
        full_name=user_data.full_name,
        campus=user_data.campus,
        department=user_data.department,
        employee_id=user_data.employee_id,
        position=user_data.position,
        contact_number=user_data.contact_number,
        created_at=datetime.now()
    )
    
    users_db[new_user.username] = new_user
    logger.info(f"New user registered: {new_user.username} from {new_user.campus}")
    return new_user

# ====== USER MANAGEMENT ENDPOINTS ======

@app.get("/users/pending", response_model=List[User])
async def get_pending_users(admin: User = Depends(get_admin_user)):
    """Get all pending users (admin only)"""
    pending_users = [u for u in users_db.values() if u.status == UserStatus.PENDING]
    return pending_users

@app.get("/users/active", response_model=List[User])
async def get_active_users(admin: User = Depends(get_admin_user)):
    """Get all active users (admin only)"""
    active_users = [u for u in users_db.values() if u.status == UserStatus.ACTIVE]
    return active_users

@app.post("/users/approve")
async def approve_user(approval: UserApproval, admin: User = Depends(get_admin_user)):
    """Approve or reject a user (admin only)"""
    user = None
    for u in users_db.values():
        if u.id == approval.user_id:
            user = u
            break
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.role == UserRole.ADMIN:
        raise HTTPException(status_code=400, detail="Use admin management for admin accounts")
    
    if approval.approved:
        user.status = UserStatus.ACTIVE
        user.role = approval.role if approval.role else UserRole.REQUESTER
        user.approved_by = admin.username
        user.approved_at = datetime.now()
        message = "User approved successfully"
    else:
        user.status = UserStatus.REJECTED
        user.approved_by = admin.username
        user.approved_at = datetime.now()
        user.comments = approval.comments
        message = "User rejected"
    
    user.updated_at = datetime.now()
    user.updated_by = admin.username
    
    logger.info(f"User {user.username} {message.lower()}")
    return {"message": message, "user": user}

@app.get("/admins", response_model=List[User])
async def get_all_admins(current_user: User = Depends(get_super_admin)):
    """Get all admin users (super admin only)"""
    admins = [u for u in users_db.values() if u.role == UserRole.ADMIN]
    return admins

@app.post("/admin/create", response_model=User)
async def create_admin(admin_data: AdminCreate, current_user: User = Depends(get_super_admin)):
    """Create a new admin (super admin only)"""
    if admin_data.username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    for user in users_db.values():
        if user.email == admin_data.email:
            raise HTTPException(status_code=400, detail="Email already exists")
        if user.employee_id == admin_data.employee_id:
            raise HTTPException(status_code=400, detail="Employee ID already exists")
    
    new_admin = User(
        username=admin_data.username,
        email=admin_data.email,
        password_hash=get_password_hash(admin_data.password),
        role=UserRole.ADMIN,
        status=UserStatus.ACTIVE,
        full_name=admin_data.full_name,
        campus=admin_data.campus,
        department=admin_data.department,
        employee_id=admin_data.employee_id,
        position=admin_data.position,
        contact_number=admin_data.contact_number,
        created_at=datetime.now(),
        created_by=current_user.username,
        approved_at=datetime.now(),
        approved_by=current_user.username
    )
    
    users_db[new_admin.username] = new_admin
    logger.info(f"New admin created: {new_admin.username} by {current_user.username}")
    return new_admin

@app.delete("/admin/{username}")
async def deactivate_admin(username: str, current_user: User = Depends(get_super_admin)):
    """Deactivate an admin account (super admin only)"""
    if username not in users_db:
        raise HTTPException(status_code=404, detail="Admin not found")
    
    admin = users_db[username]
    if admin.role != UserRole.ADMIN:
        raise HTTPException(status_code=400, detail="User is not an admin")
    
    if username == current_user.username:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    
    admin.status = UserStatus.INACTIVE
    admin.updated_at = datetime.now()
    admin.updated_by = current_user.username
    
    logger.info(f"Admin {username} deactivated by {current_user.username}")
    return {"message": f"Admin {username} deactivated successfully"}

@app.put("/users/{username}", response_model=User)
async def update_user(username: str, update_data: UserUpdate, current_user: User = Depends(get_current_active_user)):
    """Update user information"""
    if username not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    
    user = users_db[username]
    
    if current_user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN] and current_user.username != username:
        raise HTTPException(status_code=403, detail="Cannot update other users")
    
    update_dict = update_data.dict(exclude_unset=True)
    for field, value in update_dict.items():
        setattr(user, field, value)
    
    user.updated_at = datetime.now()
    user.updated_by = current_user.username
    
    return user

@app.post("/users/change-password")
async def change_password(password_change: PasswordChange, current_user: User = Depends(get_current_active_user)):
    """Change user password"""
    if not change_user_password(current_user, password_change.old_password, password_change.new_password):
        raise HTTPException(status_code=400, detail="Incorrect old password")
    
    return {"message": "Password changed successfully"}

@app.get("/me", response_model=User)
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    """Get current user information"""
    return current_user

# ====== BUDGET REQUEST ENDPOINTS ======

@app.post("/requests", response_model=BudgetRequest)
async def create_request(request_data: BudgetRequestCreate, current_user: User = Depends(get_current_active_user)):
    """Create a new budget request (requester only)"""
    if current_user.role != UserRole.REQUESTER:
        raise HTTPException(status_code=403, detail="Only requesters can create requests")
    
    new_request = BudgetRequest(
        **request_data.dict(),
        requester_id=current_user.id,
        requester_name=current_user.full_name,
        requester_email=current_user.email,
        campus=current_user.campus,
        department=current_user.department
    )
    
    budget_requests_db[new_request.id] = new_request
    logger.info(f"New budget request created: {new_request.id} by {current_user.username}")
    return new_request

@app.get("/requests/my", response_model=List[BudgetRequest])
async def get_my_requests(current_user: User = Depends(get_current_active_user)):
    """Get current user's budget requests"""
    user_requests = [r for r in budget_requests_db.values() if r.requester_id == current_user.id]
    user_requests.sort(key=lambda x: x.created_at, reverse=True)
    return user_requests

@app.get("/requests/pending", response_model=List[BudgetRequest])
async def get_pending_requests(admin: User = Depends(get_admin_user)):
    """Get all pending budget requests (admin only)"""
    pending_requests = [r for r in budget_requests_db.values() if r.status == RequestStatus.PENDING]
    pending_requests.sort(key=lambda x: x.created_at, reverse=True)
    return pending_requests

@app.get("/requests/all", response_model=List[BudgetRequest])
async def get_all_requests(admin: User = Depends(get_admin_user)):
    """Get all budget requests (admin only)"""
    requests = list(budget_requests_db.values())
    requests.sort(key=lambda x: x.created_at, reverse=True)
    return requests

@app.post("/requests/{request_id}/review")
async def review_request(request_id: str, review: BudgetRequestReview, admin: User = Depends(get_admin_user)):
    """Approve or reject a budget request (admin only)"""
    if request_id not in budget_requests_db:
        raise HTTPException(status_code=404, detail="Request not found")
    
    request = budget_requests_db[request_id]
    request.status = review.status
    request.comments = review.comments
    request.admin_notes = review.admin_notes
    request.rejection_reason = review.rejection_reason
    request.reviewed_by = admin.username
    request.reviewed_at = datetime.now()
    request.updated_at = datetime.now()
    
    if review.status == RequestStatus.APPROVED:
        request.approved_by = admin.username
        request.approved_at = datetime.now()
        request.progress = 100
        message = "Request approved"
    elif review.status == RequestStatus.REJECTED:
        request.progress = 0
        message = "Request rejected"
    elif review.status == RequestStatus.IN_REVIEW:
        request.progress = 50
        message = "Request in review"
    
    logger.info(f"{message}: {request_id} by {admin.username}")
    return {"message": message, "request": request}

@app.delete("/requests/{request_id}")
async def delete_request(request_id: str, current_user: User = Depends(get_current_active_user)):
    """Delete a budget request"""
    if request_id not in budget_requests_db:
        raise HTTPException(status_code=404, detail="Request not found")
    
    request = budget_requests_db[request_id]
    
    if current_user.role == UserRole.REQUESTER:
        if request.requester_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not your request")
        if request.status not in [RequestStatus.PENDING, RequestStatus.REJECTED]:
            raise HTTPException(status_code=400, detail="Can only delete pending or rejected requests")
    
    del budget_requests_db[request_id]
    return {"message": "Request deleted successfully"}

@app.put("/requests/{request_id}", response_model=BudgetRequest)
async def update_request(request_id: str, update_data: BudgetRequestUpdate, current_user: User = Depends(get_current_active_user)):
    """Update a budget request"""
    if request_id not in budget_requests_db:
        raise HTTPException(status_code=404, detail="Request not found")
    
    request = budget_requests_db[request_id]
    
    if current_user.role == UserRole.REQUESTER:
        if request.requester_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not your request")
        if request.status != RequestStatus.PENDING:
            raise HTTPException(status_code=400, detail="Can only update pending requests")
    
    update_dict = update_data.dict(exclude_unset=True)
    for field, value in update_dict.items():
        setattr(request, field, value)
    
    request.updated_at = datetime.now()
    return request

# ====== STATISTICS AND LOGS ======

@app.get("/stats")
async def get_stats(admin: User = Depends(get_admin_user)):
    """Get system statistics (admin only)"""
    total_requests = len(budget_requests_db)
    total_users = len(users_db)
    
    active_users = len([u for u in users_db.values() if u.status == UserStatus.ACTIVE])
    pending_users = len([u for u in users_db.values() if u.status == UserStatus.PENDING])
    admin_count = len([u for u in users_db.values() if u.role == UserRole.ADMIN])
    requester_count = len([u for u in users_db.values() if u.role == UserRole.REQUESTER])
    
    campus_stats = {}
    for user in users_db.values():
        if user.status == UserStatus.ACTIVE:
            campus_stats[user.campus] = campus_stats.get(user.campus, 0) + 1
    
    if total_requests == 0:
        request_stats = {"message": "No requests found"}
    else:
        status_counts = {}
        category_totals = {}
        campus_request_stats = {}
        total_amount = 0
        
        for request in budget_requests_db.values():
            status_counts[request.status.value] = status_counts.get(request.status.value, 0) + 1
            category_totals[request.category.value] = category_totals.get(request.category.value, 0) + request.amount
            campus_request_stats[request.campus] = campus_request_stats.get(request.campus, 0) + 1
            total_amount += request.amount
        
        request_stats = {
            "total_requests": total_requests,
            "total_amount": total_amount,
            "average_amount": total_amount / total_requests,
            "status_breakdown": status_counts,
            "category_breakdown": category_totals,
            "campus_breakdown": campus_request_stats
        }
    
    return {
        "users": {
            "total": total_users,
            "active": active_users,
            "pending": pending_users,
            "admins": admin_count,
            "requesters": requester_count,
            "campus_breakdown": campus_stats
        },
        "requests": request_stats
    }

@app.get("/activity-logs", response_model=List[ActivityLog])
async def get_activity_logs(limit: int = 100, admin: User = Depends(get_admin_user)):
    """Get recent activity logs (admin only)"""
    logs = sorted(activity_logs_db, key=lambda x: x.timestamp, reverse=True)[:limit]
    return logs

# ====== HEALTH CHECK ======

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "users": len(users_db),
        "requests": len(budget_requests_db),
        "version": "2.0.0"
    }