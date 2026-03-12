from typing import Dict, List
from app.models import User, BudgetRequest, ActivityLog
from datetime import datetime

# Databases
users_db: Dict[str, User] = {}
budget_requests_db: Dict[str, BudgetRequest] = {}
activity_logs_db: List[ActivityLog] = []

# Sample super admin
SUPER_ADMIN = {
    "username": "superadmin",
    "email": "superadmin@system.com",
    "password": "SuperAdmin123!",
    "full_name": "System Super Administrator",
    "campus": "Main Headquarters",
    "department": "IT Administration",
    "employee_id": "SA-001",
    "position": "System Administrator",
    "contact_number": "09123456789"
}

# Sample regular admin
SAMPLE_ADMIN = {
    "username": "admin",
    "email": "admin@company.com",
    "password": "admin123",
    "full_name": "Budget Administrator",
    "campus": "Main Campus",
    "department": "Finance",
    "employee_id": "AD-001",
    "position": "Budget Officer",
    "contact_number": "09234567890"
}