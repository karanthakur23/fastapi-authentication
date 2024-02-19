from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

load_dotenv()
database_url = (
        "postgresql://"
        + os.environ["POSTGRES_USER"]
        + ":"
        + os.environ["POSTGRES_PASSWORD"]
        + "@"
        + os.environ["POSTGRES_SERVER"]
        + "/"
        + os.environ["POSTGRES_DB"]
)
# Create a PostgreSQL engine instance
engine = create_engine(database_url)
# Create declarative base meta instance
Base = declarative_base()
# Create session local class for session maker

SessionLocal = sessionmaker (bind=engine, expire_on_commit=False)
