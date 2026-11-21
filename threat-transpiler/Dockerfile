FROM python:3.10-slim

WORKDIR /app

# Copy pyproject.toml first for caching dependencies
COPY pyproject.toml .

# Install runtime dependencies
RUN pip install --no-cache-dir fastapi uvicorn pydantic pyyaml

# Copy the rest of the application files
COPY . .

EXPOSE 5005

# Start uvicorn server in app package
CMD ["uvicorn", "threat_transpiler.app:app", "--host", "0.0.0.0", "--port", "5005"]
