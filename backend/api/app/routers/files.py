
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.services.file_service import FileService

router = APIRouter(
    prefix="/files",
    tags=["Files"],
)


@router.get(path="/get_file_list/{user_id}", status_code=status.HTTP_200_OK)
async def get_file_list(user_id: int, service: FileService = Depends(), session: AsyncSession = Depends(get_session)):
    return await service.get_file_list(session=session, user_id=user_id)


@router.get(path="/download_file/{user_id}/{file_name}", status_code=status.HTTP_200_OK)
async def download_file(
    user_id: int, file_name: str, service: FileService = Depends(), session: AsyncSession = Depends(get_session)
):
    return await service.download_file(session=session, user_id=user_id, file_name=file_name)
