import logging

from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import schemas
from app.core.database import get_session
from app.models import User
from app.services.user import UserService

router = APIRouter(
    prefix="/user",
    tags=["User"],
)


@router.post(path="/register/", status_code=status.HTTP_201_CREATED)
async def register_user(
    user: schemas.UserCreate, service: UserService = Depends(), session: AsyncSession = Depends(get_session)
):
    return await service.register_users(session=session, user=user)


@router.post(path="/upload/", status_code=status.HTTP_201_CREATED)
async def upload_file(
    user_id: int, file: UploadFile, service: UserService = Depends(), session: AsyncSession = Depends(get_session)
):
    if not file.filename.endswith((".txt", ".pdf", ".jpg", ".png")):  # Example allowed extensions
        raise HTTPException(status_code=400, detail="Invalid file type")

    if file.size > 10 * 1024 * 1024:  # 10 MB limit
        raise HTTPException(status_code=400, detail="File size exceeds limit")

    async with session.begin():
        stmt = select(User).filter(User.id == user_id)
        result = await session.execute(stmt)
        user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        response = await service.upload_file(session=session, user=user, file=file)
        return response
    except HTTPException as e:
        raise e
    except Exception as e:
        logging.error(f"Unexpected error during file upload: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred")


@router.post(path="/login/", status_code=status.HTTP_200_OK)
async def login_user(
    user: schemas.UserLogIn, service: UserService = Depends(), session: AsyncSession = Depends(get_session)
):
    return await service.login_user(session=session, user=user)
