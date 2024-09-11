from datetime import datetime
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import ValidationError
from pymongo import MongoClient
from jose import jwt
from schemas import SystemUser, TokenPayload
from utils import ALGORITHM, JWT_SECRET_KEY, create_access_token, create_refresh_token, verify_password

mongo = MongoClient("mongodb://localhost:27017/")
db = mongo["billauto"]
users = db["users"]

reuseable_oauth = OAuth2PasswordBearer(
    tokenUrl="/login",
    scheme_name="JWT"
)

async def get_current_user(token: str = Depends(reuseable_oauth)) -> SystemUser:
    try:
        payload = jwt.decode(
            token, JWT_SECRET_KEY, algorithms=[ALGORITHM]
        )
        token_data = TokenPayload(**payload)

        if datetime.fromtimestamp(token_data.exp) < datetime.now():
            raise HTTPException(
                status_code = status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except(jwt.JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = users.find_one({"email":token_data.sub})
    user["id"] = str(user["_id"])
    del user["_id"]
    

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Could not find user",
        )
    
    return SystemUser(**user)



app = FastAPI()

@app.get("/")
async def index():
    return {"message":"Hello, World!"}

@app.get("/secretpage")
async def secretpage(user:SystemUser = Depends(get_current_user)):
    return {"message":"i am secret"}

@app.get("/secretpagetoken")
async def secretpagetoken(token:str):
    user = await get_current_user(token)
    return user

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password
    user = users.find_one({"email":username})
    if user == None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password"
        )
    hashed_pwd = user["password"]
    if not verify_password(password, hashed_pwd):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password"
        )
    return {
        "access_token": create_access_token(user['email']),
        "refresh_token": create_refresh_token(user['email']),
    }
