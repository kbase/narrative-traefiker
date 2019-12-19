FROM python:3.6-alpine

# Build arguments passed into the docker command for image metadata
ARG BUILD_DATE
ARG COMMIT
ARG BRANCH

COPY requirements.txt /requirements.txt

# RUN pip install requests docker python-json-logger structlog && \
RUN pip3 install --upgrade pip && \
    pip install -r /requirements.txt

COPY *.py logging.conf *.conf /app/

LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url="https://github.com/kbase/narrative-traefiker.git" \
      org.label-schema.vcs-ref=$COMMIT \
      org.label-schema.schema-version="1.0.0-rc1" \
      us.kbase.vcs-branch=$BRANCH  \
      maintainer="Steve Chan sychan@lbl.gov"

COPY app.py /app/app.py
WORKDIR /app

USER root

ENTRYPOINT [ "gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--log-config", "logging.conf", "app:app" ]