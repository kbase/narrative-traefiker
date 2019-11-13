FROM jazzdd/alpine-flask:python3

COPY app.py /app/app.py

RUN pip install requests docker python-json-logger structlog && \
    sed -i 's/nginx/root/' /app.ini && \
    sed -i 's/user nginx/user root/' /etc/nginx/nginx.conf

USER root
