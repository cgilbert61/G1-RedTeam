FROM python:3.10-slim

# Install system dependencies, curl, and Node.js (for promptfoo)
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    git \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-install promptfoo globally to avoid download delay at runtime
RUN npm install -g promptfoo

COPY . .

CMD ["python", "main.py"]
