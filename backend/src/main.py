import os
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from src.core.config import settings

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
)

# Set up CORS middleware - restrict to allowed origins from environment
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,  # Only allow specified origins
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],  # Restrict methods
    allow_headers=["Content-Type", "Authorization"],  # Restrict headers
)

@app.get("/")
async def root():
    return {"message": "Welcome to VectorGuard!"}

# TODO: Add API routes, database connection, etc.