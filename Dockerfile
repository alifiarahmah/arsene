FROM ubuntu:22.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y wget curl unzip openjdk-17-jdk chromium-browser xvfb python3 python3-pip && rm -rf /var/lib/apt/lists/*

# Set JAVA_HOME
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# Download and install OWASP ZAP
RUN wget -q https://github.com/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2_16_1_unix.sh -O /tmp/zap_install.sh && chmod +x /tmp/zap_install.sh && /tmp/zap_install.sh -q && rm /tmp/zap_install.sh

# Add ZAP to PATH
ENV PATH="/root/ZAP_2.16.0:$PATH"

# Install Python dependencies for automation
RUN pip3 install selenium requests

# Create working directory
WORKDIR /workspace

# Create directories for output
RUN mkdir -p /workspace/output /workspace/scripts

# Copy scripts
COPY capture_har.py /workspace/scripts/
COPY start.sh /workspace/

# Make startup script executable
RUN chmod +x /workspace/start.sh

# Set display for headless operation
ENV DISPLAY=:99

# Expose ZAP port
EXPOSE 8080

# Default command
CMD ["/workspace/start.sh", "python3", "/workspace/scripts/capture_har.py"]