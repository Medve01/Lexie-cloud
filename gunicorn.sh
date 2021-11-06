#!/bin/sh
gunicorn wsgi:app -w 1 --threads 1 --worker-class eventlet -b 127.0.0.1:5001