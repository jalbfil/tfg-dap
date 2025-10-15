# app/db/models.py
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Text, Integer, DateTime
from datetime import datetime, timezone

class Base(DeclarativeBase):
    pass

class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    jti: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    jwt: Mapped[str] = mapped_column(Text)

    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    exp: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default="valid")
