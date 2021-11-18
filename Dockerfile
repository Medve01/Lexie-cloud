FROM python:3.9-alpine

ENV PYTHONFAULTHANDLER=1 \
  PYTHONUNBUFFERED=1 \
  PYTHONHASHSEED=random \
  PIP_NO_CACHE_DIR=off \
  PIP_DISABLE_PIP_VERSION_CHECK=on \
  PIP_DEFAULT_TIMEOUT=100 \
  POETRY_VERSION=1.1.8
RUN apk add --no-cache gcc libressl-dev musl-dev libffi-dev g++
RUN pip install "poetry==$POETRY_VERSION"

WORKDIR /lexie_cloud
COPY poetry.lock pyproject.toml /lexie_cloud/

RUN poetry config virtualenvs.create false \
  && poetry install --no-dev --no-interaction --no-ansi
# COPY requirements.txt requirements.txt
# RUN apk add gcc python-dev
# RUN pip3 install --upgrade pip
# RUN pip3 install -r requirements.txt

RUN apk del libressl-dev musl-dev libffi-dev gcc g++

COPY . /lexie_cloud

RUN mkdir /lexie_cloud/tokens
EXPOSE 5001

ENTRYPOINT [ "gunicorn", "wsgi:app", "-w", "1", "--threads", "1", "--worker-class", "eventlet", "-b", "0.0.0.0:5001" ]