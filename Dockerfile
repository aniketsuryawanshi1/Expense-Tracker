# Use the official Python slim image as a base
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory
WORKDIR /app

# Install system dependencies required for MySQL
RUN apt-get update && apt-get install -y \
    gcc \
    libmariadb-dev \
    libmariadb-dev-compat \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*  # Clean up to reduce image size

# Copy dependency file and install dependencies
COPY requirements.txt /app/
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the project files
COPY . /app/

# Change permissions to avoid permission issues
RUN chmod +x manage.py

# Default command
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "ExpenseTracker.wsgi:application"]
