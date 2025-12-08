#!/usr/bin/env bash

#
# -----------------------------------------------------------
#               03-deploy-mattermost.sh
#
#  The "Town Square" script.
#  Deploys Mattermost Enterprise (Entry Mode).
#
#  1. Network: Connects to 'cicd-net' for internal comms.
#  2. Ports:
#     - 8065 (TCP): Main UI/API (Exposed to LAN).
#     - 8443 (UDP): Calls Plugin SFU (Exposed to LAN).
#     - 8067 (TCP): Metrics (Exposed to Localhost).
#  3. Trust:   Mounts Host's ca-certificates.crt (Distroless fix).
#  4. Config:  Injects 'mattermost.env' (12-Factor).
#
# -----------------------------------------------------------

set -e
echo "🚀 Deploying Mattermost (Town Square)..."

# --- 1. Define Paths ---
HOST_CICD_ROOT="$HOME/cicd_stack"
MATTERMOST_BASE="$HOST_CICD_ROOT/mattermost"
SCOPED_ENV_FILE="$MATTERMOST_BASE/mattermost.env"

# --- 2. Prerequisite Checks ---
if [ ! -f "$SCOPED_ENV_FILE" ]; then
    echo "ERROR: mattermost.env not found."
    echo "Please run 01-setup-mattermost.sh first."
    exit 1
fi

# --- 3. Volume Management ---
echo "--- Verifying Storage Volumes ---"
docker volume create mattermost-data >/dev/null
docker volume create mattermost-logs >/dev/null
docker volume create mattermost-plugins >/dev/null
docker volume create mattermost-client-plugins >/dev/null
# Note: Bleve indexes volume removed (Deprecated in v11)

# --- 4. Clean Slate ---
if [ "$(docker ps -q -f name=mattermost)" ]; then
    echo "Stopping existing 'mattermost'..."
    docker stop mattermost
fi
if [ "$(docker ps -aq -f name=mattermost)" ]; then
    echo "Removing existing 'mattermost'..."
    docker rm mattermost
fi

# --- 5. Deploy ---
echo "--- Launching Container ---"

# CRITICAL PORTS:
# 8065: Main HTTP traffic (LAN access)
# 8443/udp: Calls Plugin Media/SFU (LAN access for calls)
# 8067: Metrics (Localhost only, for Prometheus later)

docker run -d \
  --name mattermost \
  --restart always \
  --network cicd-net \
  --hostname mattermost.cicd.local \
  --publish 0.0.0.0:8065:8065 \
  --publish 0.0.0.0:8444:8444/udp \
  --publish 0.0.0.0:8444:8444/tcp \
  --publish 127.0.0.1:8067:8067 \
  --env-file "$SCOPED_ENV_FILE" \
  --volume "$MATTERMOST_BASE/config":/mattermost/config:rw \
  --volume "$MATTERMOST_BASE/certs":/mattermost/certs:ro \
  --volume mattermost-data:/mattermost/data \
  --volume mattermost-logs:/mattermost/logs \
  --volume mattermost-plugins:/mattermost/plugins \
  --volume mattermost-client-plugins:/mattermost/client/plugins \
  --volume /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro \
  mattermost/mattermost-enterprise-edition:release-11

echo "✅ Mattermost deployed."
echo "   - Main URL: https://mattermost.cicd.local:8065"
echo "   - Metrics:  http://127.0.0.1:8067/metrics"
echo "   - Logs:     docker logs -f mattermost"
echo "   - Trust:    Host CA bundle injected."