from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    db_connection_string: str = Field(validation_alias="db_connection_string")
    # NOTE: set to True to dubug sqlalchemy queries
    db_echo: bool = False


settings = Settings(
    _env_file=".env",
    _env_file_encoding="utf-8",
)
