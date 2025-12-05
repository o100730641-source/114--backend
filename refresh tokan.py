from fastapi import FastAPI, Depends, HTTPException, status, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()

# 假資料
fake_users_db = {
    "alice": {"username": "alice", "password": "secret123"}
}

# JWT 設定
SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7  # 新增：Refresh Token 的期限 (例如 7 天)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# 通用的 Token 建立函式
def create_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_access_token(data: dict):
    return create_token(data, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

def create_refresh_token(data: dict):
    return create_token(data, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), response: Response = None):
    user = fake_users_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # 1. 建立 Access Token (短效)
    access_token = create_access_token(data={"sub": user["username"]})
    
    # 2. 建立 Refresh Token (長效)
    refresh_token = create_refresh_token(data={"sub": user["username"]})

    # 設定 Access Token 到 Cookie (原本的邏輯)
    response.set_cookie(
        key="jwt",
        value=access_token,
        httponly=True,
        samesite="lax"
    )

    # 3. 設定 Refresh Token 到 Cookie (安全性關鍵：HttpOnly)
    # 建議加上 path="/refresh" 讓這個 cookie 只在刷新時才發送，增加安全性
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="lax",
        # path="/refresh" # 視需求開啟，開啟後只有打 /refresh api 會帶此 cookie
    )
    
    return {
        "access_token": access_token, 
        "refresh_token": refresh_token, 
        "token_type": "bearer"
    }

@app.get("/protected")
def protected(token: Optional[str] = Depends(oauth2_scheme), jwt_cookie: Optional[str] = Cookie(None)):
    if token:
        username = verify_token(token)
    elif jwt_cookie:
        username = verify_token(jwt_cookie)
    else:
        raise HTTPException(status_code=401, detail="Missing token or cookie")

    return {"message": f"Hello, {username}! You are authenticated."}

# 新增：刷新 Token 的 Endpoint
@app.post("/refresh")
def refresh_token_endpoint(response: Response, refresh_token: Optional[str] = Cookie(None)):
    """
    接收 cookie 中的 refresh_token，驗證成功後回傳新的 access_token
    """
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")

    try:
        # 1. 驗證 Refresh Token
        username = verify_token(refresh_token)
        
        # 這裡通常建議要檢查資料庫，確認該使用者是否還存在，或者該 Refresh Token 是否被撤銷 (Revoked)
        # user = get_user_from_db(username) 
        
        # 2. 發放新的 Access Token
        new_access_token = create_access_token(data={"sub": username})
        
        # 3. 更新 Cookie (可選，看你要不要同時更新 cookie 中的 access token)
        response.set_cookie(
            key="jwt",
            value=new_access_token,
            httponly=True,
            samesite="lax"
        )
        
        return {"access_token": new_access_token, "token_type": "bearer"}
        
    except HTTPException as e:
        raise e
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")