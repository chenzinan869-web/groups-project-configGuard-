# ================================
# ConfigGuard - Docker Image
# Misconfiguration Scanner for Docker & Cloud Environments
# ================================

# Use official Python 3.10 slim image as base
FROM python:3.10-slim

# Set metadata
LABEL name="ConfigGuard" \
      version="1.0" \
      description="CLI scanner for docker-compose.yml misconfigurations" \
      authors="Noud Peters, Aymane Derkaoui, Zinan Chen, Abdirahman Hassan"

# Set working directory inside the container
WORKDIR /app

# Copy requirements first (for Docker layer caching)
# This means Docker won't reinstall packages unless requirements.txt changes
COPY requirements.txt .

# Install all Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project files into the container
COPY . .

# Set the entry point — this runs when the container starts
ENTRYPOINT ["python", "main.py"]
