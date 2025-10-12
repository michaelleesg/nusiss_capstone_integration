FROM python:3.12-slim

# Install system dependencies for PDF processing, spaCy, and other tools
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY pyproject.toml /app/
COPY app/ /app/app/
COPY README.md /app/

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Download spaCy English model
RUN python -m spacy download en_core_web_sm

# Create output directory
RUN mkdir -p /app/out /app/data

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV OUTPUT_DIR=/app/out

# Expose MCP TCP port (if using TCP transport)
EXPOSE 8765

# Default command (can be overridden in docker-compose)
CMD ["python", "-m", "app.cli", "--help"]
