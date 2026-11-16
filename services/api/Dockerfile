FROM python:3.12-slim

# Непривилегированный пользователь (урок ЛР0): процесс в контейнере — не root
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser \
    && install -d -m 0700 -o appuser -g appuser /var/lib/gateway/state /var/lib/gateway/private

WORKDIR /app
COPY services/api/app.py .
COPY bus ./bus
COPY privacy ./privacy
COPY config/privacy.toml ./config/privacy.toml

ENV PYTHONDONTWRITEBYTECODE=1

USER appuser
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"
CMD ["python", "-u", "app.py"]
