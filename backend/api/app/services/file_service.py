import base64
from typing import Any

from fastapi import HTTPException
from sqlalchemy import (
    select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import File, User


class FileService:
    table = File

    @classmethod
    async def _validate_existing_users(cls, session: AsyncSession, user_id: User):
        stmt = select(User).filter(User.id == user_id)
        res = await session.execute(stmt)
        existing_user = res.scalars().first()
        if not existing_user:
            raise HTTPException(status_code=400, detail="User nor found")

    @classmethod
    async def get_file_list(cls, session: AsyncSession, user_id: User) -> list[dict[str, Any]]:
        try:
            await cls._validate_existing_users(session=session, user_id=user_id)

            stmt = select(File.name).filter(File.owner_id == user_id)
            res = await session.execute(stmt)
            files = res.mappings().all()
            return files
        except IntegrityError:
            raise HTTPException(status_code=400, detail="User already exists")

    @classmethod
    async def download_file(cls, session: AsyncSession, user_id: int, file_name: str) -> dict[str, Any]:
        try:
            stmt = select(File).where((File.name == file_name) & (File.owner_id == user_id))
            result = await session.execute(stmt)
            res = result.scalars().first()
            base64_encoded_data = base64.b64encode(res.data).decode("utf-8")
            return {"name": res.name, "data": base64_encoded_data}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Unexpected error: {e!s}")
