FROM python:3.11-slim

# 1. Install system dependencies and uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 2. Copy the configuration AND the README (Crucial!)
COPY pyproject.toml README.md ./

# 3. Copy the actual source code
COPY src/ ./src/

# 4. Install
RUN uv pip install --system -e .

# 5. Expose the port
EXPOSE 8000

# 6. Run the API using the absolute package path
CMD ["uvicorn", "port_report.api.main:app", "--host", "0.0.0.0", "--port", "8000"]