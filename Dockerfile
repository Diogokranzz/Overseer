# PROJECT OVERSEER - Attack Surface Mapper
# Multi-stage build for minimal image size

FROM python:3.11-slim

# Metadata
LABEL maintainer="Red Team Operator"
LABEL description="Passive Reconnaissance Tool for External Attack Surface Mapping"
LABEL version="1.0"

# Security: create non-root user
RUN useradd --create-home --shell /bin/bash overseer

# Set working directory
WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Fix permissions
RUN chown -R overseer:overseer /app

# Switch to non-root user
USER overseer

# Entrypoint
ENTRYPOINT ["python", "overseer.py"]

# Default help
CMD ["--help"]
