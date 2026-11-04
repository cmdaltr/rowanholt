# Anduril: the only Rowanholt container that mounts the Docker socket.
# Build context is the repository root (see docker-compose.yml).
FROM python:3.12-alpine

WORKDIR /app
COPY src/common/anduril /app/anduril
COPY src/web/anduril/server.py /app/anduril_server.py

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 5690
# Runs as root: the socket inside the Docker Desktop / OrbStack VM is root-owned.
CMD ["python3", "/app/anduril_server.py"]
