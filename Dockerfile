# PHP2Shell Sentinel — Toolkit container
# Runs the Python assessment toolkit (NOT the vulnerable PHP lab)

FROM python:3.12-slim

LABEL org.opencontainers.image.title="PHP2Shell Sentinel"
LABEL org.opencontainers.image.description="PHP Runtime Vulnerability Assessment Toolkit"
LABEL org.opencontainers.image.licenses="MIT"

# Non-root user for principle of least privilege
RUN groupadd --gid 1001 sentinel && \
    useradd --uid 1001 --gid sentinel --shell /bin/bash --create-home sentinel

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e ".[dev]"

USER sentinel

ENTRYPOINT ["php2shell-sentinel"]
CMD ["--help"]
