# 1. Use the version that matches your pyproject.toml
FROM python:3.11-slim

# 2. Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# 3. Copy configuration files (README is MANDATORY if referenced in pyproject.toml)
COPY pyproject.toml README.md ./

# 4. Copy the source code
COPY src/ ./src/

# 5. Install the project
# We use --system to install into the container's python environment
RUN uv pip install --system -e .

# 6. Set environment variables to ensure Streamlit is found
# PYTHONUNBUFFERED=1 Prints logs immediately PYTHONDONTWRITEBYTECODE=1 Prevents .pyc file creation
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8501

# 7. Run Streamlit using the module path for better reliability
CMD ["streamlit", "run", "src/port_report/ui/app.py", "--server.port=8501", "--server.address=0.0.0.0"]