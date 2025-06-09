FROM ubuntu:20.04

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    net-tools \
    iputils-ping \
    tcpdump \
    iperf3 \
    iproute2 \
    git \
    curl \
    vim \
    mininet \
    openvswitch-switch \
    hping3 \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Copy requirements file first to leverage Docker cache
COPY requirements.txt .

# Install Python packages from requirements file
RUN pip3 install -r requirements.txt

# Copy the rest of the project files
COPY . .

# Expose ports
EXPOSE 6633 8080 5000

# Start script
COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]
