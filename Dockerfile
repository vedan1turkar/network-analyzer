# DONET Network Analyzer - Docker Image
# Multi-stage build for small image size

FROM python:3.11-slim as builder

# Install system dependencies for scapy
RUN apt-get update && apt-get install -y \
    gcc \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Copy application
WORKDIR /app
COPY . .

# Make donet command available
ENV PATH=/root/.local/bin:$PATH
RUN pip install --no-cache-dir --break-system-packages .

# Create non-root user for security
RUN useradd -m -u 1000 donet && chown -R donet:donet /app
USER donet

# Default command
CMD ["donet", "--help"]
