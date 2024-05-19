from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(max_length=30)
    hashed_password: str = Field(max_length=30)
    email: str | None = None
    full_name: str | None = None

