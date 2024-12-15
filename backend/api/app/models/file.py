from sqlalchemy import Column, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import relationship

from app.models.base import Base


class File(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    data = Column(LargeBinary)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User")
