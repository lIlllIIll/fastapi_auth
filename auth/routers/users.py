from typing import Annotated, List
from datetime import timedelta

from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Session
from jose import JWTError, jwt

from auth.db import get_session, init_db
from auth.models import User
from auth.schemas import User as SchemeUser, HTTPError, AdditionalUserDataForm, Token, TokenData, UserInDB, UserUpdate
from auth.security import create_access_token, verify_password, get_password_hash
from auth.config import ACCESS_TOKEN_EXPIRE_MINUTES, SECRET_KEY, ALGORITHM

router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={404: {"description": "Not found"}},
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/login")


@router.on_event("startup")
async def on_startup():
    init_db()


@router.post("/register",
             responses={
                 409: {
                     "model": HTTPError,
                     "description": "This username is already taken",
                 },
             },
             )
async def registration(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
        session: Session = Depends(get_session),
        additional_data: AdditionalUserDataForm = Depends()
) -> SchemeUser:
    user = session.query(User).filter_by(username=form_data.username).one_or_none()
    if user:
        raise HTTPException(status_code=400, detail='This username is already taken')

    hashed_password = get_password_hash(form_data.password)
    new_user = User(username=form_data.username, hashed_password=hashed_password,
                    email=additional_data.email, full_name=additional_data.full_name)
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    return new_user


@router.post("/login",
             responses={
                 401: {
                     "model": HTTPError,
                     "description": "Incorrect username or password",
                 },
             },
             )
async def login(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
        session: Session = Depends(get_session)
) -> Token:
    user = session.query(User).filter_by(username=form_data.username).one_or_none()

    if not user:
        raise HTTPException(status_code=401, detail='Incorrect username or password')
    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail='Incorrect username or password')

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@router.get("/me",
            responses={
                401: {
                    "model": HTTPError,
                    "description": "Could not validate credentials",
                },
            },
            )
async def get_user_info(
        token: str = Depends(oauth2_scheme),
        session: Session = Depends(get_session)
) -> SchemeUser:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail='Incorrect username or password')

        token_data = TokenData(username=username)
    except JWTError:
        raise HTTPException(status_code=401, detail='Could not validate credentials',
                            headers={"WWW-Authenticate": "Bearer"})
    user = session.query(User).filter_by(username=token_data.username).one_or_none()
    if user is None:
        raise HTTPException(status_code=401, detail='Could not validate credentials',
                            headers={"WWW-Authenticate": "Bearer"})
    return user


@router.put("/me",
            responses={
                401: {
                    "model": HTTPError,
                    "description": "Could not validate credentials",
                },
            },
            )
async def update_user_info(
        data_for_update: UserUpdate,
        token: str = Depends(oauth2_scheme),
        session: Session = Depends(get_session),
) -> SchemeUser:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail='Incorrect username or password')

        token_data = TokenData(username=username)
    except JWTError:
        raise HTTPException(status_code=401, detail='Could not validate credentials',
                            headers={"WWW-Authenticate": "Bearer"})
    user = session.query(User).filter_by(username=token_data.username).one_or_none()
    if user is None:
        raise HTTPException(status_code=401, detail='Could not validate credentials',
                            headers={"WWW-Authenticate": "Bearer"})

    if data_for_update.username:
        user.username = data_for_update.username
    if data_for_update.password:
        user.hashed_password = get_password_hash(data_for_update.password)
    if data_for_update.email:
        user.email = data_for_update.email
    if data_for_update.full_name:
        user.full_name = data_for_update.full_name

    session.add(user)
    session.commit()
    session.refresh(user)

    return user


@router.delete("/delete",
               responses={
                   401: {
                       "model": HTTPError,
                       "description": "Could not validate credentials",
                   },
               },
               )
async def delete_user(
        token: str = Depends(oauth2_scheme),
        session: Session = Depends(get_session),
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail='Incorrect username or password')

        token_data = TokenData(username=username)
    except JWTError:
        raise HTTPException(status_code=401, detail='Could not validate credentials',
                            headers={"WWW-Authenticate": "Bearer"})

    user = session.query(User).filter_by(username=token_data.username).one_or_none()
    if user is None:
        raise HTTPException(status_code=401, detail='Could not validate credentials',
                            headers={"WWW-Authenticate": "Bearer"})

    session.delete(user)
    session.commit()
    return {"message": "The user has been successfully deleted"}
