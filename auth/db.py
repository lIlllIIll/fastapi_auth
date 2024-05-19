from auth.config import DB_URL
from sqlmodel import SQLModel, create_engine, Session
from auth.models import User


postgres_url = DB_URL


engine = create_engine(postgres_url)


def init_db():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session
