from .schemas import *
from . import models
from .models import User, TokenTable
from .database import Base, engine, SessionLocal
from fastapi import FastAPI, Depends, HTTPException,status, Query, Request, Form
from sqlalchemy.orm import Session
import jwt
from datetime import datetime
from fastapi.security import OAuth2PasswordBearer
from .auth_bearer import JWTBearer
from functools import wraps
from .utils import create_access_token,create_refresh_token,verify_password,get_hashed_password, create_access_token_for_forgot_password
from .auth_bearer import JWTBearer
from .email_notifications.notify import send_reset_password_mail
from fastapi.responses import RedirectResponse, HTMLResponse
from pathlib import Path
from fastapi.templating import Jinja2Templates
import os

templates_directory = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_directory))

ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 2  # 2 days
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # 7 days
ALGORITHM = "HS256"

Base.metadata.create_all(engine)

def get_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

app = FastAPI()

# Decorator to see if current token is expired or not
def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        payload = jwt.decode(kwargs['dependencies'], os.environ["JWT_SECRET_KEY"], ALGORITHM)
        user_id = payload['sub']
        data= kwargs['session'].query(models.TokenTable).filter_by(user_id=user_id, access_token=kwargs['dependencies'],status=True).first()
        if data:
            return func(kwargs['dependencies'],kwargs['session'])
        else:
            return {'msg': "Token blocked"}
    return wrapper

# To register a user
@app.post('/register')
def register(user: UserCreate, session: Session = Depends(get_session)):
    existing_user = session.query(models.User).filter_by(email=user.email).first()
    if existing_user:
        raise HTTPException(status_code=404, datail="Email already registered")

    encrypted_password = get_hashed_password(user.password)
    new_user = models.User(username=user.username, email=user.email, password=encrypted_password)

    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    return {'message': 'User Registered Successfully'}

# To login a user
@app.post('/login', response_model=TokenSchema)
def login(request: requestdetails, session: Session = Depends(get_session)):
    user = session.query(models.User).filter_by(email=request.email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Incorrect Email')
    hash_password = user.password

    if not verify_password(request.password, hash_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Incorrect Password')

    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)

    new_token = models.TokenTable(user_id=user.id, access_token=access_token, refresh_token=refresh_token, status=True)
    session.add(new_token)
    session.commit()
    session.refresh(new_token)

    return {
        'access_token': access_token,
        'refresh_token': refresh_token
    }

# To get all users
@app.get('/getusers')
@token_required
def getusers(session: Session = Depends(get_session), dependencies=Depends(JWTBearer())):
    user = session.query(models.User).all()
    return user

# To change a password
@app.post('/change-password')
@token_required
def change_password(request: changepassword, session: Session = Depends(get_session), dependencies=Depends(JWTBearer())):
    user = session.query(models.User).filter_by(email=request.email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='User Not Found')

    if not verify_password(request.old_password, user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Old Password is Incorrect')

    encrypted_password = get_hashed_password(request.new_password)
    user.password = encrypted_password
    session.commit()

    return {
        'messsage': 'Password Changed Successfully'
    }

# To logout a user
@app.post('/logout')
@token_required
def logout(session: Session = Depends(get_session), dependencies=Depends(JWTBearer())):
    token = dependencies
    payload = jwt.decode(token, os.environ["JWT_SECRET_KEY"], algorithms=ALGORITHM)
    user_id = payload['sub']
    token_record = session.query(models.TokenTable).all()
    info = []

    for record in token_record:
        if (datetime.utcnow() - record.created_at).days > 1:
            info.append(record.user_id)

    if info:
        existing_token = session.query(models.TokenTable).where(TokenTable.user_id.in_(info)).delete()
        db.commit()

    existing_token = session.query(models.TokenTable).filter(models.TokenTable.user_id == user_id, models.TokenTable.access_token == token).first()
    if existing_token:
        existing_token.status = False
        session.add(existing_token)
        session.commit()
        session.refresh(existing_token)
    return {
        'message': 'Logout Successfully'
    }

# To update a forgotten password through email
@app.post('/forgot-password')
@token_required
async def forgot_password(email: str, session: Session = Depends(get_session)):
    TEMP_TOKEN_EXPIRE_MINUTES = 10
    try:
        user = session.query(User).filter(User.email == email).first()
        if user:
            access_token = create_access_token_for_forgot_password(data=email, expire_minutes=TEMP_TOKEN_EXPIRE_MINUTES)
            url = f'http://127.0.0.1:8000/reset_password_template?access_token={access_token}&email={email}'
            await send_reset_password_mail(recipient_email=email, user=user, url=url, expire_in_minutes=TEMP_TOKEN_EXPIRE_MINUTES)
            return RedirectResponse(url)
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"An unexpected error occurred(forgot_password). Report this message to support: {e}")

# To render a template for change password
@app.get("/reset_password_template",
              response_class=HTMLResponse,
              summary="Reset password for a user", tags=["Users"])
def user_reset_password_template(request: Request):
    try:
        token = request.query_params.get('access_token')
        email = request.query_params.get('email')

        return templates.TemplateResponse(
            "reset_password.html",
            {
                "request": request,
                "email": email,
                "access_token": token
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"An unexpected error occurred(r_p_template). Report this message to support: {e}")

# To update/save the user's changed password in db
@app.post("/reset_password",
              summary="Resets password for a user", tags=["Users"])
def user_reset_password(request: Request, new_password: str = Form(...), confirm_password: str = Form(...), session: Session = Depends(get_session)):
    try:
        if new_password != confirm_password:
            raise HTTPException(status_code=400, detail="Passwords do not match")
        email = request.query_params.get('email')
        user = session.query(models.User).filter(models.User.email == email).first()
        if user:
            user.password = get_hashed_password(new_password)
            session.commit()
            return {"message": "Password reset successfully"}
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {e}")