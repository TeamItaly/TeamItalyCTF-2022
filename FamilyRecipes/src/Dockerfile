FROM python:3.8.2-slim-buster

# Update and install packages
RUN apt-get update
RUN apt-get install -y --no-install-recommends \
    qemu-system-x86 \
    socat

# Create directory for challenge files
RUN mkdir -p /opt/

# Copy challenge entrypoint
COPY entrypoint.sh \
     /opt/
WORKDIR /opt/

# Socat listening port
EXPOSE 1337

# Change entrypoint to launch challenge
CMD ["./entrypoint.sh"]
