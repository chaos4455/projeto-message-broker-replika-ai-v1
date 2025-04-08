# Dockerfile for message-broker-replika

# ---- Base Image ----
# Use Ubuntu 22.04 LTS as the base image
FROM ubuntu:22.04 AS base

# ---- Environment Variables ----
# Set non-interactive frontend for package installations
ENV DEBIAN_FRONTEND=noninteractive
# Define the application directory
ENV APP_HOME=/home/replika/app

# ---- System Dependencies ----
# Update package lists, upgrade existing packages, install necessary system packages, and clean up
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        openssh-server \
        supervisor \
        # Utilities often helpful for debugging inside the container:
        curl \
        git \
        net-tools \
        iputils-ping \
        nano \
        netcat \
    && rm -rf /var/lib/apt/lists/*

# ---- User and SSH Setup ----
# Create a non-root user 'admin' and set a default password (INSECURE: Change for Production!)
# Configure SSH server for basic password authentication and listening on all interfaces.
RUN useradd -m -s /bin/bash admin && \
    echo "admin:admin" | chpasswd && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    # Ensure SSH listens on all interfaces within the container
    sed -i 's/^#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/' /etc/ssh/sshd_config && \
    sed -i 's/^#ListenAddress ::/ListenAddress ::/' /etc/ssh/sshd_config && \
    # Create the runtime directory for sshd
    mkdir -p /var/run/sshd

# ---- Application Setup ----
# Create the application directory
WORKDIR ${APP_HOME}

# Copy only the requirements file first to leverage Docker cache
# Assumes requirements.txt is inside an 'app' subdirectory in the build context
COPY app/requirements.txt ${APP_HOME}/requirements.txt

# Install Python dependencies
RUN if [ -f "${APP_HOME}/requirements.txt" ]; then \
        pip3 install --no-cache-dir -r ${APP_HOME}/requirements.txt; \
    else \
        echo "WARNING: requirements.txt not found in app/, skipping pip install."; \
    fi

# Copy the rest of the application code from the 'app' subdirectory
# Assumes the Dockerfile is in the parent directory of 'app'
COPY app/ ${APP_HOME}/

# ---- Supervisor Configuration ----
# Copy the supervisor configuration file into the container
# Assumes supervisord.conf is in the root of the build context (alongside Dockerfile)
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# ---- Networking ----
# Expose the ports that the services within the container will listen on
# This is documentation; actual port publishing happens with `docker run -p` or docker-compose/k8s config.
EXPOSE 22    # SSH Server
EXPOSE 8777  # FastAPI API
EXPOSE 8333  # Flask Dashboard
EXPOSE 8555  # Streamlit WebApp

# ---- Runtime ----
# Set the default command to run supervisord in the foreground
# -c specifies the configuration file explicitly
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
