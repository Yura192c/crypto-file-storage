
from pydantic import BaseModel


class UserCreate(BaseModel):
    username: str
    public_key: str
    password: str


class UserLogIn(BaseModel):
    username: str
    password: str
