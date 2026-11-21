# NETGUARD — Containerized Production Deployment
# Note: Network intrusion detection requires host network mode to capture L2 ARP broadcast packets.
FROM python:3.11-slim

# Install system packet capture libraries (libpcap) and networking utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    net-tools \
    iproute2 \
    wireless-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Expose Web Interface Port
EXPOSE 5000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_ENV=production

# Run production WSGI server
CMD ["python", "server.py"]
