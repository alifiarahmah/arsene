#!/bin/bash

# Start Xvfb for headless operation
Xvfb :99 -screen 0 1024x768x24 &

# Start ZAP in daemon mode
zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=".*" -config api.addrs.addr.regex=true &

# Wait for ZAP to start
sleep 10

# Execute the provided command or default script
exec "$@"