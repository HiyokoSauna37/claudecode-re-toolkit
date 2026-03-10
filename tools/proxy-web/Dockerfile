FROM python:3.11-slim

# Install Chromium and dependencies
RUN apt-get update && apt-get install -y \
    chromium \
    chromium-driver \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libatspi2.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libwayland-client0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    xdg-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages (cryptography for in-container AES encryption)
RUN pip install --no-cache-dir playwright cryptography

# Set Playwright browsers path to shared location
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN mkdir -p /ms-playwright && \
    playwright install chromium && \
    chmod -R 755 /ms-playwright

# Create non-root user
RUN useradd -m -u 1000 sandboxuser && \
    mkdir -p /app /output /tmp/downloads && \
    chown -R sandboxuser:sandboxuser /app /output /tmp/downloads

# Copy browser script
COPY browser_script.py /app/

# Switch to non-root user
USER sandboxuser
WORKDIR /app

# Set environment
ENV PYTHONUNBUFFERED=1

# Default command
CMD ["python", "browser_script.py"]
