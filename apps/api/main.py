"""
FinCipher AI — High-Scale Standalone API Gateway Service
Author: Om Kamble
"""

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.api.main import app as core_app

app = core_app

if __name__ == "__main__":
    uvicorn.run("apps.api.main:app", host="0.0.0.0", port=8000, reload=False, workers=2)
