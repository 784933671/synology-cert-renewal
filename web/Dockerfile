FROM node:26-alpine@sha256:c6ad9e9c1d80f6eb607c26b4b0a132ff7a2344fad1c78ea3baa2a7d4c8de6d94 AS ui
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-alpine@sha256:e6dae589c1c05976188fd3bd019afd091445fc533ed2ea29001beddc7368a9c8
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
# 上游稳定镜像暂未包含 SQLite FTS5 修复；仅补官方签名单包，不切换系统仓库。
RUN test "$(apk --print-arch)" = x86_64 \
    && if ! python -c 'import sqlite3; assert sqlite3.sqlite_version_info >= (3, 54, 0)'; then \
      python -c 'import hashlib,pathlib,urllib.request; data=urllib.request.urlopen("https://dl-cdn.alpinelinux.org/alpine/edge/main/x86_64/sqlite-libs-3.54.1-r0.apk",timeout=60).read(2000000); assert hashlib.sha256(data).hexdigest()=="5dfd76936e795efd988d6bad4949b8d20c410d6dc9dd256da884111f668f3915"; pathlib.Path("/tmp/sqlite-libs.apk").write_bytes(data)' \
      && apk add --no-network --no-cache /tmp/sqlite-libs.apk \
      && rm /tmp/sqlite-libs.apk; \
    fi \
    && python -c 'import sqlite3; assert sqlite3.sqlite_version_info >= (3, 54, 0); print("SQLite", sqlite3.sqlite_version)'
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY __init__.py /app/web/__init__.py
COPY backend/ /app/web/backend/
COPY container_entry.py healthcheck.py access_policy.py /app/web/
COPY --from=ui /build/dist/ /app/static/
RUN chmod -R a+rX /app/web /app/static
USER 10100:10100
ENTRYPOINT ["python", "-m", "web.container_entry"]
