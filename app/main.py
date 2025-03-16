import os

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from loguru import logger
from pydantic import BaseModel, HttpUrl, ValidationError

from app.routes import pac
from app.utils.logger import setup_logger

root_path = os.environ.get("ROOT_PATH", "")
app = FastAPI(root_path=root_path)
templates = Jinja2Templates(directory="app/templates")

# Setup logger
setup_logger()

# Include routes
app.include_router(pac.router)
