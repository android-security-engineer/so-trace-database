from fastapi import APIRouter, Depends, HTTPException, status, Response
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.user import User
from utils.auth import hash_password, verify_password, create_access_token, create_refresh_token, decode_token
from config import settings

router = APIRouter(prefix="/auth", tags=["auth"])


class Credentials(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int


class StatusResponse(BaseModel):
    setup_required: bool


@router.get("/status", response_model=StatusResponse)
async def check_status(db: AsyncSession = Depends(get_db)):
    count = await db.scalar(select(func.count()).select_from(User))
    return {"setup_required": count == 0}


@router.post("/setup", response_model=TokenResponse)
async def setup(creds: Credentials, db: AsyncSession = Depends(get_db)):
    count = await db.scalar(select(func.count()).select_from(User))
    if count > 0:
        raise HTTPException(status_code=400, detail="Already set up")

    user = User(username=creds.username, password_hash=hash_password(creds.password))
    db.add(user)
    await db.commit()

    payload = {"sub": creds.username}
    return {
        "access_token": create_access_token(payload),
        "refresh_token": create_refresh_token(payload),
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


@router.post("/login", response_model=TokenResponse)
async def login(creds: Credentials, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == creds.username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(creds.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    payload = {"sub": user.username}
    return {
        "access_token": create_access_token(payload),
        "refresh_token": create_refresh_token(payload),
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


@router.post("/refresh", response_model=TokenResponse)
async def refresh(token: str = Depends(lambda req: req.headers.get("Authorization", "").removeprefix("Bearer "))):
    data = decode_token(token)
    if not data or data.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    payload = {"sub": data["sub"]}
    return {
        "access_token": create_access_token(payload),
        "refresh_token": create_refresh_token(payload),
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }
