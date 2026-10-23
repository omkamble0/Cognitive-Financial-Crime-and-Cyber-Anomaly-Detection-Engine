"""
FinCipher AI — Web Dashboard Serving Layer
Author: Om Kamble
"""

import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

web_app = FastAPI(title="FinCipher AI Web Studio")

DASHBOARD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../dashboard"))

if os.path.exists(DASHBOARD_DIR):
    web_app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")

    @web_app.get("/")
    def index():
        return FileResponse(os.path.join(DASHBOARD_DIR, "index.html"))
