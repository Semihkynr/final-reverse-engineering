# ============================================================
# Dockerfile — Reverse Engineering Analysis Framework
# BGT210 · Istinye University · Semih Kaynar
# ============================================================
FROM python:3.11-slim

LABEL maintainer="Semih Kaynar <semihkynr@github>"
LABEL description="BGT210 RE Framework — Static Binary Analyzer"
LABEL university="Istinye University"
LABEL course="BGT210 Reverse Engineering"

WORKDIR /app

# System dependencies for pefile, capstone, yara
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    libffi-dev \
    build-essential \
    file \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY src/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY docs/ ./docs/

# Create directories
RUN mkdir -p /app/reports /app/samples /app/logs /app/tmp

# Non-root user for security
RUN useradd -m -u 1000 analyst && chown -R analyst:analyst /app
USER analyst

ENTRYPOINT ["python", "src/analyzer.py"]
CMD ["--help"]
