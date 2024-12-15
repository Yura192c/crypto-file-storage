import bcrypt
from sqlalchemy import Column, Integer, LargeBinary, String

from app.models.base import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    public_key = Column(String)
    symmetric_key = Column(LargeBinary)
    password_hash = Column(String, nullable=True, default="")  # Хэш пароля вместо самого пароля

    # Метод для хэширования пароля
    def set_password(self, password: str):
        """Хэширует пароль перед сохранением"""
        self.password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    # Метод для проверки пароля
    def check_password(self, password: str) -> bool:
        """Проверяет, соответствует ли введённый пароль хэшу"""
        return bcrypt.checkpw(password.encode("utf-8"), self.password_hash.encode("utf-8"))
