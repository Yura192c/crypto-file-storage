FROM python:3.12.4-slim-bookworm as requirements-stage

WORKDIR /tmp

RUN apt-get update && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y

RUN pip install poetry

COPY ./poetry.lock* ./pyproject.toml /tmp/

RUN poetry export -f requirements.txt --output requirements.txt --without-hashes

FROM python:3.12.4-slim-bookworm

WORKDIR /code

COPY --from=requirements-stage /tmp/requirements.txt /code/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt


# ! Database migrations are currently integrated into the Dockerfile and executed during FastAPI startup.
# ! This solution effectively handles migrations at the moment.
# ! However, in the future, it may be beneficial to consider separating migration process
# ! into a distinct pipeline for improved modularity and flexibility
RUN pip install alembic
COPY ./migrations /code/migrations
COPY ./alembic.ini /code/alembic.ini

# COPY ./log_config.yaml /code/log_config.yaml
COPY ./app /code/app

# ! Run alembic migrarions and next FastAPI back-end
CMD alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8080 --log-config=log_config.yaml