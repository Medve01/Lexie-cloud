FROM python:3.9-alpine
COPY requirements.txt requirements.txt
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
COPY . /lexie_cloud
WORKDIR /lexie_cloud

ENTRYPOINT [ "gunicorn.sh" ]