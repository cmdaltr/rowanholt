FROM python:3.12-slim

WORKDIR /app

# Install system dependencies and forensic tools
RUN apt-get update && apt-get install -y \
    build-essential \
    libvshadow-utils \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies (pip first: the base image's has advisories of its own)
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /tmp/elrond/output /tmp/elrond/uploads

# Expose port
EXPOSE 5688

# Default command (can be overridden in docker-compose)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5688"]
