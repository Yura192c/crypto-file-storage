from pydantic import BaseModel


class FileResponse(BaseModel):
    id: int
    name: str

    class Config:
        orm_mode = True


class FileUploadResponse(BaseModel):
    message: str
    file_id: int


class FileUploadRequest(BaseModel):
    user_id: int
    file_name: str
    data: str  # Base64-encoded encrypted file data
    nonce: str  # Base64-encoded nonce
    tag: str  # Base64-encoded tag for AES verification
    symmetric_key: str  # Base64-encoded encrypted symmetric key
