FROM python:3.11-slim

# 1. Install system dependencies
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 2. Copy config first (Optimization: keeps layers cached)
COPY pyproject.toml README.md ./

# 3. Copy source code
COPY src/ ./src/

# 4. Install dependencies (The slow part - now cached unless pyproject.toml changes)
RUN uv pip install --system -e .

# 5. Copy scripts LAST (So editing a script doesn't trigger a full pip reinstall)
COPY scripts/ ./scripts/

EXPOSE 8000

CMD ["uvicorn", "port_report.api.main:app", "--host", "0.0.0.0", "--port", "8000"]