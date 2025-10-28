# GitHub SBOM Consolidator Docker Image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
COPY pyproject.toml .
COPY setup.py .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ src/
COPY config/ config/
COPY README.md .
COPY LICENSE .
COPY MANIFEST.in .

# Install the package
RUN pip install -e .

# Create output directory
RUN mkdir -p /app/output

# Set environment variables
ENV PYTHONPATH=/app/src
ENV SBOM_OUTPUT_DIR=/app/output

# Create non-root user
RUN useradd --create-home --shell /bin/bash sbom
RUN chown -R sbom:sbom /app
USER sbom

# Expose volume for output
VOLUME ["/app/output"]

# Default command
ENTRYPOINT ["sbom-consolidator"]
CMD ["--help"]