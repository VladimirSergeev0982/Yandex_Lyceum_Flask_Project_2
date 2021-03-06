import pytz
import datetime
import sqlalchemy

from .db_session import SqlAlchemyBase


class Session(SqlAlchemyBase):
    __tablename__ = 'sessions'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True, nullable=False, unique=True,
                           index=True)
    user = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id"), nullable=True, index=True)
    key = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    salt = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    csrf_token = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    created_date = sqlalchemy.Column(sqlalchemy.DateTime, default=datetime.datetime.now(pytz.timezone("UTC")))
