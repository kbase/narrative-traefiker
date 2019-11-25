FROM jazzdd/alpine-flask:python3

COPY app.py /app/app.py

RUN pip install requests docker python-json-logger structlog && \
    sed -i 's/nginx/root/' /app.ini && \
    sed -i 's/user nginx/user root/' /etc/nginx/nginx.conf

LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url="https://github.com/kbase/narrative-traefiker.git" \
      org.label-schema.vcs-ref=$COMMIT \
      org.label-schema.schema-version="1.0.0-rc1" \
      us.kbase.vcs-branch=$BRANCH  \
      maintainer="Steve Chan sychan@lbl.gov"


USER root
