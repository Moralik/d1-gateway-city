FROM python:3.12-alpine
WORKDIR /app
COPY local_broker.py ./
RUN addgroup -g 10001 app && adduser -D -u 10001 -G app app && mkdir /data && chown app:app /data
USER app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 BROKER_HOST=0.0.0.0 BROKER_DB=/data/broker.sqlite3
EXPOSE 14167
ENTRYPOINT ["python", "local_broker.py"]
