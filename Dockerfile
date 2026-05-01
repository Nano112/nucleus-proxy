FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Install uv
RUN pip install uv

# Copy project files
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Copy application code
COPY . .

# Ensure data directories exist (for volume mounting points)
RUN mkdir -p data/staging data/logs

# Add venv to PATH
ENV PATH="/app/.venv/bin:$PATH"

# Expose port
EXPOSE 8088

# Run the application
CMD ["python", "run.py"]

