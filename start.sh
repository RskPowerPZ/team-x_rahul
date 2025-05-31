#!/usr/bin/env bash
gunicorn --worker-class gevent --workers 4 --bind 0.0.0.0:$PORT app:app
