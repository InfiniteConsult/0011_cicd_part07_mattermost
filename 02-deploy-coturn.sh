#!/usr/bin/env bash

#
# -----------------------------------------------------------
#               02-deploy-coturn.sh
#
#  The "Radio Tower" script.
#  Deploys a Coturn STUN/TURN server for WebRTC media relay.
#
#  1. Network: Uses '--network host' to bypass Docker NAT.
#  2. Config:  Injects the shared secret generated in Step 01.
#  3. Identity: Auto-detects LAN IP for the --external-ip flag.
#
# -----------------------------------------------------------

set -e
echo "🚀 Deploying Coturn (Radio Tower)..."

# --- 1. Load Secrets ---
MASTER_ENV_FILE="$HOME/cicd_stack/cicd.env"
if [ ! -f "$MASTER_ENV_FILE" ]; then
    echo "ERROR: Master env file not found at $MASTER_ENV_FILE"
    exit 1
fi
source "$MASTER_ENV_FILE"

if [ -z "$MATTERMOST_TURN_SECRET" ]; then
    echo "ERROR: MATTERMOST_TURN_SECRET not found in cicd.env"
    echo "Please run 01-setup-mattermost.sh first."
    exit 1
fi

# --- 2. Detect Host IP ---
# We need to tell Coturn what its external IP is so it can
# advertise it to clients (phones/browsers).
# hostname -I returns all IPs; awk '{print $1}' takes the first one.
LAN_IP=$(hostname -I | awk '{print $1}')

if [ -z "$LAN_IP" ]; then
    echo "ERROR: Could not detect LAN IP."
    exit 1
fi

echo "📡 Radio Tower Configuration:"
echo "   - Listening IP: 0.0.0.0"
echo "   - External IP:  $LAN_IP (Advertised to clients)"
echo "   - Realm:        mattermost.cicd.local"
echo "   - Network:      Host Mode (Bypassing Docker Bridge)"

# --- 3. Clean Slate ---
if [ "$(docker ps -q -f name=coturn)" ]; then
    echo "Stopping existing 'coturn'..."
    docker stop coturn
fi
if [ "$(docker ps -aq -f name=coturn)" ]; then
    echo "Removing existing 'coturn'..."
    docker rm coturn
fi

# --- 4. Deploy ---
# We use the official coturn image.
# We pass configuration flags directly to the command.
# Note: --network host is critical here for UDP performance.

docker run -d \
  --name coturn \
  --network host \
  --restart always \
  coturn/coturn \
  -n \
  --log-file=stdout \
  --min-port=49152 \
  --max-port=65535 \
  --realm=mattermost.cicd.local \
  --listening-ip=0.0.0.0 \
  --external-ip=$LAN_IP \
  --use-auth-secret \
  --static-auth-secret=$MATTERMOST_TURN_SECRET

echo "✅ Coturn deployed."
echo "   Verify logs with: docker logs -f coturn"
