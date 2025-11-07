from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from jose import JWTError, jwt
import hashlib
from typing import Optional, List
import os

# -------------------------------------------------
# Uygulama
# -------------------------------------------------
app = FastAPI(title="A'LIXE Backend", version="1.0.0")

# -------------------------------------------------
# CORS AYARI
# -------------------------------------------------
# Ortam değişkenlerinden oku (Render'da FRONTEND_ORIGIN olarak ayarlayabilirsin)
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "https://panel.alixestore.com")

origins = [
    FRONTEND_ORIGIN,       # Canlı panel domaini
    "http://localhost:5173",  # Lokal geliştirme (Vite)
]

# None veya boş olanları temizle
origins = [o for o in origins if o]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------
# JWT AYARLARI
# -------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")  # Render'da SECRET_KEY ayarlayabilirsin
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# -------------------------------------------------
# IN-MEMORY KULLANICI VERİSİ
# -------------------------------------------------
users_db: List[dict] = []


# -------------------------------------------------
# YARDIMCI FONKSİYONLAR
# -------------------------------------------------
def validate_password(password: str):
    """Şifre kurallarını kontrol et."""
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Şifre en az 8 karakter olmalı.")
    if not any(ch.isupper() for ch in password):
        raise HTTPException(status_code=400, detail="Şifre en az bir büyük harf içermeli.")

    # Ardışık 3 rakam kontrolü (123, 456 vs. yasak)
    for i in range(len(password) - 2):
        if password[i].isdigit() and password[i + 1].isdigit() and password[i + 2].isdigit():
            if (int(password[i + 1]) == int(password[i]) + 1 and
                    int(password[i + 2]) == int(password[i + 1]) + 1):
                raise HTTPException(
                    status_code=400,
                    detail="Şifre ardışık 3 sayı içeremez (örn. 123, 456, 789).",
                )


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> str:
    """JWT token içinden email'i (sub) döndür, hatalıysa 401 fırlat."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token geçersiz."
            )
        return email
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token hatalı veya süresi dolmuş."
        )


# -------------------------------------------------
# Pydantic MODELLERİ
# -------------------------------------------------
class RegisterUser(BaseModel):
    username: str
    email: EmailStr
    password: str


class LoginUser(BaseModel):
    email: EmailStr
    password: str


# -------------------------------------------------
# ENDPOINTLER
# -------------------------------------------------
@app.get("/health")
async def health_check():
    return {"status": "ok"}


@app.post("/register")
async def register_user(user: RegisterUser):
    # Şifre kuralı
    validate_password(user.password)

    # Email benzersiz mi?
    for u in users_db:
        if u["email"] == user.email:
            raise HTTPException(status_code=400, detail="Bu email zaten kayıtlı.")

    # İlk kullanıcı admin olsun
    is_admin = len(users_db) == 0

    users_db.append(
        {
            "username": user.username,
            "email": user.email,
            "password_hash": hash_password(user.password),
            "is_admin": is_admin,
        }
    )

    return {"message": "Kayıt başarılı."}


@app.post("/login")
async def login(data: LoginUser):
    for u in users_db:
        if u["email"] == data.email and u["password_hash"] == hash_password(data.password):
            token = create_access_token({"sub": u["email"]})
            return {"access_token": token, "token_type": "bearer"}

    raise HTTPException(status_code=401, detail="Email veya şifre hatalı.")


@app.get("/me")
async def get_me(token: str):
    email = verify_token(token)

    for u in users_db:
        if u["email"] == email:
            return {
                "username": u["username"],
                "email": u["email"],
                "is_admin": u["is_admin"],
            }

    raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı.")


@app.get("/users")
async def get_users(token: str):
    email = verify_token(token)

    caller = None
    for u in users_db:
        if u["email"] == email:
            caller = u
            break

    if caller is None:
        raise HTTPException(status_code=401, detail="Kullanıcı doğrulanamadı.")

    if not caller["is_admin"]:
        raise HTTPException(status_code=403, detail="Yetkin yok.")

    return [
        {
            "username": u["username"],
            "email": u["email"],
            "is_admin": u["is_admin"],
        }
        for u in users_db
    ]
