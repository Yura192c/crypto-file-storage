import datetime
from typing import ClassVar

from sqlalchemy import TIMESTAMP, MetaData
from sqlalchemy.orm import DeclarativeBase

POSTGRES_INDEXES_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

pg_metadata = MetaData(naming_convention=POSTGRES_INDEXES_NAMING_CONVENTION)


class Base(DeclarativeBase):
    metadata = pg_metadata

    type_annotation_map: ClassVar[dict] = {
        datetime.datetime: TIMESTAMP(timezone=False),
    }

    @classmethod
    def pk_name(cls):
        """Pick"""
        return cls.__mapper__.primary_key[0].name
