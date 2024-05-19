from typing import Annotated

from fastapi import Form
from pydantic import BaseModel
from pydantic.dataclasses import dataclass


class HTTPError(BaseModel):
    detail: str

    class Config:
        json_schema_extra = {
            "example": {"detail": "HTTPException raised."},
        }


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None


class UserInDB(User):
    password: str


class UserUpdate(BaseModel):
    username: str = None
    email: str | None = None
    full_name: str | None = None
    password: str = None


@dataclass
class AdditionalUserDataForm:
    email: Annotated[str | None, Form()] = None
    full_name: Annotated[str | None, Form()] = None


