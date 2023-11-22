# Use the official Rust image as the base image
FROM rust:latest

# Set up environment variables for Python virtual environment
ENV VENV_PATH=/usr/src/venv
ENV PATH="$VENV_PATH/bin:$PATH"

# Configure this!
ENV KEY=8cd23d813f27313f
ENV IV=e6aca7250c60bb1d
ENV COOKIE=ade49d04134299da
ENV LITCRYPT_ENCRYPT_KEY=b6c8ea4a178cdc81
ENV DOMAIN=watcher.wtl.pw
ENV USERNAME=watcher
ENV PASSWORD=watcher

# Install Redis and Python3
RUN apt-get update && apt-get install -y redis-server python3 python3-pip python3-venv

RUN python3 -m venv $VENV_PATH

# Copy your application's files into the container
COPY backend /app
COPY watcher /watcher
COPY start.sh /start.sh

WORKDIR /app
RUN python3 -m pip install -r requirements.txt

RUN chmod +x /start.sh

EXPOSE 8900

CMD ["/start.sh"]