import base64
from typing import Any

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from fastapi import HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import File, User
from app.schemas import UserCreate, UserLogIn


class UserService:
    table = User

    @classmethod
    async def _validate_existing_users(cls, session: AsyncSession, user: UserCreate):
        stmt = select(User).filter(User.username == user.username)
        res = await session.execute(stmt)
        existing_user = res.scalars().first()
        if existing_user:
            raise HTTPException(status_code=400, detail="User already exists")

    @classmethod
    async def register_users(cls, session: AsyncSession, user: UserCreate) -> dict[str, str]:
        try:
            await cls._validate_existing_users(session=session, user=user)

            try:
                rsa_public_key = RSA.import_key(user.public_key)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid public key")

            symmetric_key = get_random_bytes(16)
            cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
            encrypted_symmetric_key = cipher_rsa.encrypt(symmetric_key)

            new_user = User(username=user.username, public_key=user.public_key, symmetric_key=encrypted_symmetric_key)
            new_user.set_password(user.password)
            session.add(new_user)
            await session.commit()
            await session.refresh(new_user)

            return {"symmetric_key": base64.b64encode(symmetric_key).decode(), "user_id": new_user.id}
        except IntegrityError:
            raise HTTPException(status_code=400, detail="User already exists")

    @classmethod
    async def upload_file(cls, session: AsyncSession, user: User, file: UploadFile) -> dict[str, Any]:
        try:
            new_file = File(name=file.filename, data=file.file.read(), owner_id=user.id)
            session.add(new_file)
            await session.commit()
            await session.refresh(new_file)

            return {"detail": "File uploaded successfully"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Unexpected error: {e!s}")

    @classmethod
    async def login_user(cls, session: AsyncSession, user: UserLogIn):
        try:
            # await cls._validate_existing_users(session=session, user=username)
            stmt = select(User).filter(User.username == user.username)
            res = await session.execute(stmt)
            existing_user = res.scalars().first()
            if not existing_user:
                raise HTTPException(status_code=404, detail="User not found")
            if not existing_user.check_password(user.password):  # Используем метод check_password для проверки
                raise HTTPException(status_code=401, detail="Incorrect password")
            base64_encoded_symmetric_key = base64.b64encode(existing_user.symmetric_key).decode("utf-8")
            return {"symmetric_key": base64_encoded_symmetric_key, "user_id": existing_user.id}

        except IntegrityError:
            raise HTTPException(status_code=400, detail="User already exists")
