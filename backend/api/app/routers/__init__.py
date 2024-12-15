from fastapi import APIRouter, Security

from . import user as user_router
from . import files as file_router


router = APIRouter()
router.include_router(user_router.router)
router.include_router(file_router.router)