"""Database engine and session factory for Hybrid SIEM.

Uses SQLAlchemy with asyncpg driver for PostgreSQL.
Falls back gracefully to SQLite for local development (no PostgreSQL needed).
"""
from __future__ import annotations

import os
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

# Use DATABASE_URL env variable — defaults to in-process SQLite for local dev
DATABASE_URL = os.environ.get(
    "SIEM_DATABASE_URL",
    "sqlite+aiosqlite:///./data/siem.db",
)

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    future=True,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def init_db() -> None:
    """Create all tables if they don't exist."""
    async with engine.begin() as conn:
        from hybrid_siem.database import models as _  # noqa: F401 – side-effect import
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncSession:
    """Dependency-injectable session factory."""
    async with AsyncSessionLocal() as session:
        yield session
