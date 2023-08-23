from datetime import datetime, timedelta
from fastapi import Request
import jwt

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from cachetools import TTLCache

from schemas import Token, User, Post

app = FastAPI()


# DB Connectivity settings
DATABASE_URL = "postgresql://app_user:app_password@localhost:5432/app_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Cache settings
cache = TTLCache(maxsize=1000, ttl=300)
MAX_PAYLOAD_SIZE = 1024 * 1024
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SECRET_KEY = "your-secret-key"  # Replace with your actual secret key
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Set the token expiration time


# Initial Table creation and DataBase Connection
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    emailid = Column(String, unique=True, index=True)
    password = Column(String)
    token = Column(String)

class PostData(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    description = Column(String)
    user_emailid = Column(String, index=True)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Utility functions for token validations
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, JWT_ALGORITHM=JWT_ALGORITHM)
    return encoded_jwt

def verify_token(token: str, db: SessionLocal):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credential validation failed.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        emailid: str = payload.get("sub")
        if emailid is None:
            raise credentials_exception
        return emailid
    except jwt.ExpiredSignatureError:
        raise credentials_exception
    except jwt.JWTError:
        raise credentials_exception

def get_current_user(
    token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)
):
    user_emailid = verify_token(token, db)
    user = db.query(User).filter(User.emailid == user_emailid).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User details not found."
        )
    return user



# API Endpoints 
# Generate Token Endpoint
@app.post("/GenerateToken", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    user = db.query(User).filter(User.emailid == form_data.username).first()
    if not user or user.password != form_data.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )
    token = create_access_token({"sub": user.emailid})

    return {"access_token": token, "token_type": "bearer"}


#Endpoint for login
@app.post("/Login")
def login(emailid: str, password: str, db: SessionLocal = Depends(get_db)):
    user = (
        db.query(User)
        .filter(User.emailid == emailid, User.password == password)
        .first()
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials."
        )
    token = create_access_token({"sub": user.emailid})

    return Token(access_token=token, token_type="bearer")


#Endpoint for Create user
@app.post("/Signup")
def signup(emailid: str, password: str, db: SessionLocal = Depends(get_db)):
    user = db.query(User).filter(User.emailid == emailid).first()
    if user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists."
        )
    token = create_access_token({"sub": emailid})
    new_user = User(emailid=emailid, password=password, token=token)
    db.add(new_user)
    db.commit()

    return {"message": "Signup successful"}


# Endpoint for create post
@app.post("/CreatePost")
def add_post(
    post: Post,
    user: User = Depends(get_current_user),
    db: SessionLocal = Depends(get_db),
):
    # Payload validation
    if len(post.description.encode()) > MAX_PAYLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload size exceeds maximum limit.",
        )
    new_post = PostData(description=post.description, user_emailid=user.emailid)
    db.add(new_post)
    db.commit()

    return {"message": "Post created successfully."}


#Endpoint to retrieve the posts based on login user 
@app.get("/GetPosts")
def get_posts(
    request: Request,
    user: User = Depends(get_current_user),
    db: SessionLocal = Depends(get_db),
):
    cached_posts = cache.get(user.emailid)
    if cached_posts:
        return cached_posts
    user_posts = db.query(PostData).filter(PostData.user_emailid == user.emailid).all()
    user_posts = [{"postID": post.id, "description": post.description} for post in user_posts]
    response_size = len(str(user_posts).encode())
    if response_size <= MAX_PAYLOAD_SIZE:
        cache[user.emailid] = user_posts

    return user_posts


# Endpoint to delete a post
@app.delete("/DeletePost")
def delete_post(
    post_id: int,
    user: User = Depends(get_current_user),
    db: SessionLocal = Depends(get_db),
):
    post = (
        db.query(PostData)
        .filter(PostData.id == post_id, PostData.user_emailid == user.emailid)
        .first()
    )
    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Post details not exists."
        )
    db.delete(post)
    db.commit()

    return {"message": "Post deleted successfully."}
