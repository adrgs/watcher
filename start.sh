#!/bin/sh

# Start Redis server in the background
redis-server --daemonize yes

cd /watcher
cargo build --release

cd /app
# Execute the Python application
exec python3 main.py