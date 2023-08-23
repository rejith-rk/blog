from pydantic import BaseModel


# Table Schemas
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    emailid: str = None

class User(BaseModel):
    emailid: str

class Post(BaseModel):
    description: str

