# Builds eudi-srv-statuslist-py for dev/bdd use.
# Upstream reference: eudi-srv-pid-issuer docker-compose/status-list/Dockerfile @ v0.10.1
FROM python:3.14.6-alpine3.24
ARG VERSION=v0.9.0

RUN \
  wget "https://github.com/eu-digital-identity-wallet/eudi-srv-statuslist-py/archive/refs/tags/${VERSION}.zip" -O /tmp/app.zip && \
  unzip /tmp/app.zip && \
  mv eudi-srv-statuslist-py-* status-list && \
  rm /tmp/app.zip

WORKDIR /status-list

COPY get_status_list.py /tmp/get_status_list.py
RUN cat /tmp/get_status_list.py >> app/status_list_endpoints.py && rm /tmp/get_status_list.py

RUN sed -i 's|"url": "https://issuer.eudiw.dev"|"url": "http://localhost"|' app/static/swagger.json

RUN \
  pip install --no-cache-dir Flask && \
  pip install --no-cache-dir -r app/requirements.txt

EXPOSE 5000

CMD [ "flask", "--app", "app", "run", "--host=0.0.0.0" ]
