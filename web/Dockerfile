FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS ui
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY __init__.py /app/web/__init__.py
COPY backend/ /app/web/backend/
COPY container_entry.py healthcheck.py access_policy.py /app/web/
COPY --from=ui /build/dist/ /app/static/
RUN chmod -R a+rX /app/web /app/static
USER 10100:10100
ENTRYPOINT ["python", "-m", "web.container_entry"]
