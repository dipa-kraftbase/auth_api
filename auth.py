from fastapi import APIRouter, HTTPException, Header
from database import supabase
from pydanticModels import *
from configuration import settings
import jwt

router = APIRouter()

@router.post("/signup")
def signup(request: SignupRequest):
    res = supabase.auth.sign_up({
        "email": request.email,
        "password": request.password
    })

    if not res.user:
        raise HTTPException(status_code=400, detail="Signup failed. Possibly invalid email or already registered.")

    return {"message": "Signup successful. Please verify your email."}


@router.post("/login")
def login(request: LoginRequest):
    res = supabase.auth.sign_in_with_password(request.dict())

    if not res.session or not res.user:
        raise HTTPException(status_code=400, detail="Login failed. Invalid credentials.")

    return {
        "access_token": res.session.access_token,
        "refresh_token": res.session.refresh_token,
        "user": {
            "id": res.user.id,
            "email": res.user.email
        }
    }


@router.post("/logout")
def logout(
    access_token: str = Header(..., alias="access-token"),
    refresh_token: str = Header(..., alias="refresh-token")
):
    try:
        supabase.auth.set_session(access_token=access_token, refresh_token=refresh_token)
        supabase.auth.sign_out()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Logout failed: {str(e)}")

    return {"message": "Logged out susccessfully"}


@router.post("/reset-password")
def perform_reset(
    request: PerformResetRequest,
    access_token: str = Header(..., alias="access-token")
):
    if not access_token:
        raise HTTPException(status_code=401, detail="Missing access_token header")

    token = access_token.strip()

    try:
        supabase.auth.set_session(access_token=token, refresh_token="")  
        res = supabase.auth.update_user({"password": request.new_password})
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Password reset failed: {str(e)}")

    if not res.user:
        raise HTTPException(status_code=400, detail="Password reset failed.")

    return {"message": "Password updated successfully"}

@router.get("/me")
def me(
    access_token: str = Header(..., alias="access-token")
):
    token = access_token.strip()

    try:
        decoded = jwt.decode(token, settings.SUPABASE_JWT_SECRET, algorithms=["HS256"])
        return {"user": decoded}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

