from pydantic import BaseModel
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class requestdetails(BaseModel):
    email:str
    password:str

class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str

class changepassword(BaseModel):
    email:str
    old_password:str
    new_password:str

class TokenCreate(BaseModel):
    user_id:int
    access_token:str
    refresh_token:str
    status:bool
    created_date: datetime = datetime.now()

class SetNewPassword(BaseModel):
    new_password: str
    confirm_password: str