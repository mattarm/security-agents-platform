FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY bot/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY bot/ ./bot/
COPY scripts/ ./scripts/

# Create data directory
RUN mkdir -p /app/data

# Set environment variables
ENV PYTHONPATH=/app
ENV DB_PATH=/app/data/war_rooms.db
ENV LOG_FILE_PATH=/app/data/war_room_bot.log

# Create non-root user
RUN useradd --create-home --shell /bin/bash warroom
RUN chown -R warroom:warroom /app
USER warroom

# Expose port (if needed for health checks)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python scripts/health_check.py || exit 1

# Start the bot
CMD ["python", "bot/slack_war_room_bot.py"]