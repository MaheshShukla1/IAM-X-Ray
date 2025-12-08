# -------- BUILDER --------
FROM python:3.11-slim AS builder
ENV PYTHONUNBUFFERED=1
WORKDIR /build

# System deps for building wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc g++ git curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Install python deps in isolated /install
COPY requirements.txt .
RUN pip install --upgrade pip wheel setuptools
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Copy source
COPY . /build

# Create sample snapshot
RUN python - <<'PY'
import os, json
os.makedirs("data", exist_ok=True)
p = "data/sample_snapshot.json"
if not os.path.exists(p):
    json.dump({"demo": True}, open(p,"w"))
PY

# Obfuscate core/*.py → .pyc only
RUN python -m compileall -b -q /build/core \
 && find /build/core -name "*.py" -delete

# Cleanup cache
RUN rm -rf /root/.cache || true
  
# Compute build hash
RUN (find /build -type f \
      ! -path "/build/data/*" \
      -exec sha256sum {} \; \
    | sort -k2 \
    | sha256sum \
    | awk '{print $1}') > /build/BUILD_HASH


# -------- FINAL --------
FROM python:3.11-slim AS final
ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Minimal runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN addgroup --system iamx \
 && adduser --system --ingroup iamx --home /home/iamx iamx \
 && mkdir -p /home/iamx/.streamlit /home/iamx/.cache /app/data \
 && chown -R iamx:iamx /home/iamx /app

# Copy Python libs
COPY --from=builder /install /usr/local

# Copy app
COPY --from=builder --chown=iamx:iamx /build/app /app/app
COPY --from=builder --chown=iamx:iamx /build/core /app/core
COPY --from=builder --chown=iamx:iamx /build/data /app/data
COPY --from=builder --chown=iamx:iamx /build/BUILD_HASH /app/BUILD_HASH

USER iamx

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -fsS "http://localhost:8501/?healthz=1" || exit 1

ENTRYPOINT ["sh", "-c", "\
R=$(mktemp); \
find /app -type f ! -path '/app/data/*' -not -name BUILD_HASH -exec sha256sum {} \\; \
 | sort -k2 | sha256sum | awk '{print $1}' > $R; \
cmp -s $R /app/BUILD_HASH || echo 'WARNING: build hash mismatch'; \
exec streamlit run app/main.py --server.address=0.0.0.0 --server.port=8501 --server.headless=true \
"]
