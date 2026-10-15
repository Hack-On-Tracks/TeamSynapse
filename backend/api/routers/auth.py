import os
from datetime import timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel

from ...auth.auth import create_access_token, decode_access_token, UsersDatabase

router = APIRouter()

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict

class UserLogin(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = ""
    role: Optional[str] = "analyst"

class UserResponse(BaseModel):
    id: str
    username: str
    full_name: str
    role: str
    created_at: str

def get_db():
    db = UsersDatabase()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: dict = Depends(decode_access_token)):
    username = token.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token payload",
        )
    db = UsersDatabase()
    try:
        user = db.get_user(username)
        if not user or user.get("disabled"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account inactive or not found",
            )
        return {
            "id": user["id"],
            "username": user["username"],
            "full_name": user["full_name"],
            "role": user["role"],
        }
    finally:
        db.close()

@router.post("/token", response_model=Token)
def login_for_access_token(form_data: UserLogin, request: Request, db: UsersDatabase = Depends(get_db)):
    client_ip = request.client.host if request.client else "127.0.0.1"
    user = db.authenticate(form_data.username, form_data.password, ip_address=client_ip)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")))
    access_token = create_access_token(data={"sub": user["username"], "role": user["role"]}, expires_delta=access_token_expires)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user,
    }

@router.post("/register", response_model=UserResponse)
def register_user(req: UserCreate, db: UsersDatabase = Depends(get_db), current_user: dict = Depends(get_current_user)):
    # Restrict registration to admins
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only administrators can create users")
    try:
        created = db.create_user(req.username, req.password, req.full_name or "", req.role or "analyst")
        db.log_audit_event("USER_CREATE", current_user["username"], "SUCCESS", f"Created user {req.username}")
        return created
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.get("/me")
def read_current_user(current_user: dict = Depends(get_current_user)):
    return current_user

@router.get("/audit-logs")
def read_audit_logs(limit: int = 50, db: UsersDatabase = Depends(get_db), current_user: dict = Depends(get_current_user)):
    return db.get_audit_logs(limit=limit)

