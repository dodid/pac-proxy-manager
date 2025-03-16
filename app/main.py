import asyncio
import base64
import time

import httpx
import requests
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from loguru import logger
from pydantic import BaseModel, HttpUrl, ValidationError

from app.routes import pac
from app.utils.logger import setup_logger

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# Setup logger
setup_logger()

# Include routes
app.include_router(pac.router)
