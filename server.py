from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from fastapi import FastAPI, APIRouter, Request, HTTPException, Response
from fastapi.responses import RedirectResponse
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from requests_oauthlib import OAuth2Session
from bson import ObjectId
import os
import logging
import bcrypt
import jwt
import secrets
import requests
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timezone, timedelta

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
api_router = APIRouter(prefix="/api")

JWT_ALGORITHM = "HS256"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Password Hashing ---
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

# --- JWT ---
def get_jwt_secret() -> str:
    return os.environ["JWT_SECRET"]

def create_access_token(user_id: str, email: str) -> str:
    payload = {"sub": user_id, "email": email, "exp": datetime.now(timezone.utc) + timedelta(minutes=15), "type": "access"}
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)

def create_refresh_token(user_id: str) -> str:
    payload = {"sub": user_id, "exp": datetime.now(timezone.utc) + timedelta(days=7), "type": "refresh"}
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)

def set_auth_cookies(response: Response, access_token: str, refresh_token: str):
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="none", max_age=900, path="/")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite="none", max_age=2592000, path="/")

# --- Auth Helper ---
async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user["_id"] = str(user["_id"])
        user.pop("password_hash", None)
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# --- Brute Force ---
async def check_brute_force(ip: str, email: str):
    identifier = f"{ip}:{email}"
    record = await db.login_attempts.find_one({"identifier": identifier}, {"_id": 0})
    if record and record.get("attempts", 0) >= 5:
        locked_until = record.get("locked_until")
        if locked_until and datetime.now(timezone.utc) < locked_until:
            raise HTTPException(status_code=429, detail="Too many login attempts. Try again in 15 minutes.")
        else:
            await db.login_attempts.delete_one({"identifier": identifier})

async def record_failed_attempt(ip: str, email: str):
    identifier = f"{ip}:{email}"
    record = await db.login_attempts.find_one({"identifier": identifier}, {"_id": 0})
    attempts = (record.get("attempts", 0) if record else 0) + 1
    update = {"$set": {"identifier": identifier, "attempts": attempts, "last_attempt": datetime.now(timezone.utc)}}
    if attempts >= 5:
        update["$set"]["locked_until"] = datetime.now(timezone.utc) + timedelta(minutes=15)
    await db.login_attempts.update_one({"identifier": identifier}, update, upsert=True)

async def clear_failed_attempts(ip: str, email: str):
    await db.login_attempts.delete_one({"identifier": f"{ip}:{email}"})

# --- Pydantic Models ---
class RegisterInput(BaseModel):
    email: str
    password: str
    name: str

class LoginInput(BaseModel):
    email: str
    password: str

class WaterLogInput(BaseModel):
    amount: int
    label: Optional[str] = "Water"

class SettingsInput(BaseModel):
    daily_goal: Optional[int] = None
    reminder_interval: Optional[int] = None
    notification_type: Optional[str] = None
    custom_sound: Optional[str] = None
    theme: Optional[str] = None
    reminder_enabled: Optional[bool] = None
    wake_time: Optional[str] = None
    sleep_time: Optional[str] = None
    custom_reminder_times: Optional[List[str]] = None
    quick_add_position: Optional[str] = None

class AddReminderTimeInput(BaseModel):
    time: str

class RemoveReminderTimeInput(BaseModel):
    time: str

class ForgotPasswordInput(BaseModel):
    email: str

class ResetPasswordInput(BaseModel):
    token: str
    new_password: str

class FirebaseLoginInput(BaseModel):
    token: str

# --- Auth Endpoints ---
@api_router.post("/auth/register")
async def register(input: RegisterInput, response: Response):
    raise HTTPException(status_code=403, detail="Email registration is temporarily disabled. Please use Google Login.")
    email = input.email.lower().strip()
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = hash_password(input.password)
    user_doc = {
        "email": email,
        "password_hash": hashed,
        "name": input.name,
        "role": "user",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    result = await db.users.insert_one(user_doc)
    user_id = str(result.inserted_id)
    # Create default settings
    await db.settings.insert_one({
        "user_id": user_id,
        "daily_goal": 2000,
        "reminder_interval": 60,
        "notification_type": "vibrate_sound",
        "custom_sound": "default",
        "theme": "light",
        "reminder_enabled": True,
        "wake_time": "08:00",
        "sleep_time": "22:00",
        "custom_reminder_times": [],
        "quick_add_position": "bottom-right"
    })
    access_token = create_access_token(user_id, email)
    refresh_token = create_refresh_token(user_id)
    set_auth_cookies(response, access_token, refresh_token)
    return {"_id": user_id, "email": email, "name": input.name, "role": "user"}

@api_router.post("/auth/login")
async def login(input: LoginInput, request: Request, response: Response):
    email = input.email.lower().strip()
    ip = request.client.host
    await check_brute_force(ip, email)
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(input.password, user["password_hash"]):
        await record_failed_attempt(ip, email)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if user.get("role") != "admin":
        await record_failed_attempt(ip, email)
        raise HTTPException(status_code=403, detail="Email login is restricted to administrators. Please use Google Login.")
        
    await clear_failed_attempts(ip, email)
    user_id = str(user["_id"])
    access_token = create_access_token(user_id, email)
    refresh_token = create_refresh_token(user_id)
    set_auth_cookies(response, access_token, refresh_token)
    return {"_id": user_id, "email": email, "name": user.get("name", ""), "role": user.get("role", "user")}

@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"message": "Logged out"}

@api_router.get("/auth/me")
async def get_me(request: Request):
    user = await get_current_user(request)
    return user

@api_router.post("/auth/refresh")
async def refresh_token(request: Request, response: Response):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="No refresh token")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user_id = str(user["_id"])
        access_token = create_access_token(user_id, user["email"])
        response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="none", max_age=900, path="/")
        return {"message": "Token refreshed"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

@api_router.post("/auth/forgot-password")
async def forgot_password(input: ForgotPasswordInput):
    email = input.email.lower().strip()
    user = await db.users.find_one({"email": email})
    if not user:
        return {"message": "If the email exists, a reset link has been sent."}
    token = secrets.token_urlsafe(32)
    await db.password_reset_tokens.insert_one({
        "token": token,
        "user_id": str(user["_id"]),
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
        "used": False
    })
    logger.info(f"Password reset link: /reset-password?token={token}")
    return {"message": "If the email exists, a reset link has been sent."}

@api_router.post("/auth/reset-password")
async def reset_password(input: ResetPasswordInput):
    record = await db.password_reset_tokens.find_one({"token": input.token, "used": False})
    if not record:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    if datetime.now(timezone.utc) > record["expires_at"]:
        raise HTTPException(status_code=400, detail="Token expired")
    hashed = hash_password(input.new_password)
    await db.users.update_one({"_id": ObjectId(record["user_id"])}, {"$set": {"password_hash": hashed}})
    await db.password_reset_tokens.update_one({"token": input.token}, {"$set": {"used": True}})
    return {"message": "Password reset successful"}

# --- Firebase Auth ---
FIREBASE_PROJECT_ID = "hydraflow-wra"

@api_router.post("/auth/firebase")
async def firebase_login(input: FirebaseLoginInput, response: Response):
    try:
        res = requests.get('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com')
        certs = res.json()
        
        header = jwt.get_unverified_header(input.token)
        kid = header.get('kid')
        if not kid or kid not in certs:
            raise HTTPException(status_code=401, detail="Invalid token kid")
        
        cert_str = certs[kid]
        cert_obj = load_pem_x509_certificate(cert_str.encode('utf-8'), default_backend())
        public_key = cert_obj.public_key()
        
        decoded = jwt.decode(
            input.token,
            public_key,
            algorithms=['RS256'],
            audience=FIREBASE_PROJECT_ID,
            issuer=f"https://securetoken.google.com/{FIREBASE_PROJECT_ID}"
        )
    except Exception as e:
        logger.error(f"Firebase token verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid Firebase token")
        
    email = decoded.get("email", "").lower()
    name = decoded.get("name", "Firebase User")
    
    if not email:
        raise HTTPException(status_code=400, detail="Token does not contain an email")
        
    user = await db.users.find_one({"email": email})
    if not user:
        user_doc = {
            "email": email,
            "name": name,
            "role": "user",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "firebase_uid": decoded.get("sub"),
            "is_google_user": True
        }
        result = await db.users.insert_one(user_doc)
        user_id = str(result.inserted_id)
        await db.settings.insert_one({
            "user_id": user_id,
            "daily_goal": 2000,
            "reminder_interval": 60,
            "notification_type": "vibrate_sound",
            "theme": "light",
            "reminder_enabled": True,
            "quick_add_position": "bottom-right"
        })
    else:
        user_id = str(user["_id"])

    access_token = create_access_token(user_id, email)
    refresh_token = create_refresh_token(user_id)
    set_auth_cookies(response, access_token, refresh_token)
    
    return {"_id": user_id, "email": email, "name": name, "role": user.get("role", "user") if user else "user"}

# --- Water Log Endpoints ---
@api_router.post("/water/log")
async def log_water(input: WaterLogInput, request: Request):
    user = await get_current_user(request)
    log_doc = {
        "user_id": user["_id"],
        "amount": input.amount,
        "label": input.label,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    await db.water_logs.insert_one(log_doc)
    return {"message": "Logged", "amount": input.amount, "label": input.label}

@api_router.get("/water/today")
async def get_today_water(request: Request):
    user = await get_current_user(request)
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    logs = await db.water_logs.find(
        {"user_id": user["_id"], "timestamp": {"$gte": today_start}},
        {"_id": 0}
    ).sort("timestamp", -1).to_list(100)
    total = sum(log["amount"] for log in logs)
    return {"logs": logs, "total": total}

@api_router.get("/water/history")
async def get_water_history(request: Request, days: int = 7):
    user = await get_current_user(request)
    start_date = (datetime.now(timezone.utc) - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    logs = await db.water_logs.find(
        {"user_id": user["_id"], "timestamp": {"$gte": start_date}},
        {"_id": 0}
    ).to_list(1000)
    # Group by date
    daily = {}
    for log in logs:
        date_str = log["timestamp"][:10]
        daily[date_str] = daily.get(date_str, 0) + log["amount"]
    # Build array for last N days
    result = []
    for i in range(days):
        d = (datetime.now(timezone.utc) - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")
        result.append({"date": d, "amount": daily.get(d, 0)})
    return {"history": result}

@api_router.delete("/water/log/{timestamp}")
async def delete_water_log(timestamp: str, request: Request):
    user = await get_current_user(request)
    result = await db.water_logs.delete_one({"user_id": user["_id"], "timestamp": timestamp})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Log not found")
    return {"message": "Deleted"}

@api_router.post("/water/undo")
async def undo_water(input: WaterLogInput, request: Request):
    """Remove the most recent water log matching the given amount (for undo/hold-to-remove)."""
    user = await get_current_user(request)
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    log = await db.water_logs.find_one(
        {"user_id": user["_id"], "amount": input.amount, "timestamp": {"$gte": today_start}},
        sort=[("timestamp", -1)]
    )
    if not log:
        raise HTTPException(status_code=404, detail="No matching log found to undo")
    await db.water_logs.delete_one({"_id": log["_id"]})
    return {"message": "Undone", "amount": input.amount}

# --- Settings Endpoints ---
@api_router.get("/settings")
async def get_settings(request: Request):
    user = await get_current_user(request)
    settings = await db.settings.find_one({"user_id": user["_id"]}, {"_id": 0})
    if not settings:
        settings = {
            "user_id": user["_id"],
            "daily_goal": 2000,
            "reminder_interval": 60,
            "notification_type": "vibrate_sound",
            "custom_sound": "default",
            "theme": "light",
            "reminder_enabled": True,
            "wake_time": "08:00",
            "sleep_time": "22:00",
            "custom_reminder_times": [],
            "quick_add_position": "bottom-right"
        }
        await db.settings.insert_one(settings)
        settings.pop("_id", None)
    return settings

@api_router.put("/settings")
async def update_settings(input: SettingsInput, request: Request):
    user = await get_current_user(request)
    update_data = {k: v for k, v in input.model_dump().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")
    await db.settings.update_one(
        {"user_id": user["_id"]},
        {"$set": update_data},
        upsert=True
    )
    settings = await db.settings.find_one({"user_id": user["_id"]}, {"_id": 0})
    return settings

# --- Custom Reminder Times Endpoints ---
@api_router.post("/settings/reminder-times")
async def add_reminder_time(input: AddReminderTimeInput, request: Request):
    user = await get_current_user(request)
    time_str = input.time.strip()
    # Validate time format HH:MM
    try:
        datetime.strptime(time_str, "%H:%M")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid time format. Use HH:MM")
    settings = await db.settings.find_one({"user_id": user["_id"]})
    current_times = settings.get("custom_reminder_times", []) if settings else []
    if time_str in current_times:
        raise HTTPException(status_code=400, detail="Time already exists")
    current_times.append(time_str)
    current_times.sort()
    await db.settings.update_one(
        {"user_id": user["_id"]},
        {"$set": {"custom_reminder_times": current_times}},
        upsert=True
    )
    return {"custom_reminder_times": current_times}

@api_router.delete("/settings/reminder-times")
async def remove_reminder_time(input: RemoveReminderTimeInput, request: Request):
    user = await get_current_user(request)
    time_str = input.time.strip()
    settings = await db.settings.find_one({"user_id": user["_id"]})
    current_times = settings.get("custom_reminder_times", []) if settings else []
    if time_str not in current_times:
        raise HTTPException(status_code=404, detail="Time not found")
    current_times.remove(time_str)
    await db.settings.update_one(
        {"user_id": user["_id"]},
        {"$set": {"custom_reminder_times": current_times}}
    )
    return {"custom_reminder_times": current_times}

# --- Root ---
@api_router.get("/")
async def root():
    return {"message": "Water Reminder API"}

# --- Include Router ---
app.include_router(api_router)

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:3000,https://hydraflow-app.vercel.app").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Startup ---
@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await db.password_reset_tokens.create_index("expires_at", expireAfterSeconds=0)
    await db.login_attempts.create_index("identifier")
    await db.water_logs.create_index([("user_id", 1), ("timestamp", -1)])
    await db.settings.create_index("user_id", unique=True)
    # Seed admin
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@waterreminder.com")
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    existing = await db.users.find_one({"email": admin_email})
    if existing is None:
        hashed = hash_password(admin_password)
        result = await db.users.insert_one({
            "email": admin_email,
            "password_hash": hashed,
            "name": "Admin",
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        admin_id = str(result.inserted_id)
        await db.settings.update_one(
            {"user_id": admin_id},
            {"$set": {"user_id": admin_id, "daily_goal": 2000, "reminder_interval": 60, "notification_type": "vibrate_sound", "custom_sound": "default", "theme": "light", "reminder_enabled": True, "wake_time": "08:00", "sleep_time": "22:00", "custom_reminder_times": [], "quick_add_position": "bottom-right"}},
            upsert=True
        )
        logger.info(f"Admin seeded: {admin_email}")
    elif not verify_password(admin_password, existing["password_hash"]):
        await db.users.update_one({"email": admin_email}, {"$set": {"password_hash": hash_password(admin_password)}})
        logger.info("Admin password updated")
    # Write test credentials
    memory_path = ROOT_DIR.parent / "memory"
    memory_path.mkdir(exist_ok=True)
    with open(memory_path / "test_credentials.md", "w") as f:
        f.write(f"# Test Credentials\n\n## Admin\n- Email: {admin_email}\n- Password: {admin_password}\n- Role: admin\n\n## Auth Endpoints\n- POST /api/auth/register\n- POST /api/auth/login\n- POST /api/auth/logout\n- GET /api/auth/me\n- POST /api/auth/refresh\n")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
