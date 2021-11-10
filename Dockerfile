FROM python:3.9
COPY requirements.txt requirements.txt
# RUN apk add gcc python-dev
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
COPY . /lexie_cloud
WORKDIR /lexie_cloud
RUN mkdir /lexie_cloud/tokens
EXPOSE 5001

ENTRYPOINT [ "gunicorn", "wsgi:app", "-w", "1", "--threads", "1", "--worker-class", "eventlet", "-b", "0.0.0.0:5001" ]