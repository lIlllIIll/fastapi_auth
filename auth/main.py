import uvicorn
from fastapi import FastAPI

from auth.routers import users

app = FastAPI()

app.include_router(users.router)


# uvicorn auth.main:app --reload


@app.get("/")
async def root():
    return {"message": "/docs"}

