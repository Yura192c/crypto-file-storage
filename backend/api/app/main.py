import logging

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

from app import routers

APP_NAME = "Crypto-filemanager-api"

origins = ["*"]

app = FastAPI()

app.openapi_version = "3.0.3"


app = FastAPI(
    title="Crypto Filemanager API",
    version="1.0.0",
    openapi_url="/cr/api/openapi.json",
    docs_url="/cr/api/docs",
    redoc_url="/cr/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(
    routers.router,
    prefix="/cr/api",
)


@app.get("/se/api/generate_error")
async def error_test(response: Response):
    logging.error("Got an error")
    raise ValueError("Error message")
