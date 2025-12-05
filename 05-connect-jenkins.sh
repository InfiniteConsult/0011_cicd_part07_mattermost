#!/usr/bin/env bash

#
# -----------------------------------------------------------
#               05-connect-jenkins.sh
#
#  Integrates Jenkins with Mattermost via Webhook.
#
#  1. Secrets: Reads JENKINS_MATTERMOST_WEBHOOK (host)
#              -> Injects MATTERMOST_JENKINS_WEBHOOK_URL (jenkins.env).
#  2. JCasC:   Updates jenkins.yaml with Notifier config.
#  3. Apply:   Re-deploys Jenkins.
#
# -----------------------------------------------------------

set -e

# --- Paths ---
CICD_ROOT="$HOME/cicd_stack"
# Adjust this path if your Jenkins article folder is named differently
JENKINS_MODULE_DIR="$HOME/Documents/FromFirstPrinciples/articles/0008_cicd_part04_jenkins"
JENKINS_ENV_FILE="$JENKINS_MODULE_DIR/jenkins.env"
DEPLOY_SCRIPT="$JENKINS_MODULE_DIR/03-deploy-controller.sh"

# Path to the Python helper (Local to this script)
PY_HELPER="./update_jcasc_mattermost.py"
MASTER_ENV="$CICD_ROOT/cicd.env"

echo "[INFO] Starting Jenkins <-> Mattermost Integration..."

# --- 1. Secret Injection ---
if [ ! -f "$MASTER_ENV" ]; then
    echo "[ERROR] Master environment file not found: $MASTER_ENV"
    exit 1
fi

# Load secrets
source "$MASTER_ENV"

if [ -z "$JENKINS_MATTERMOST_WEBHOOK" ]; then
    echo "[ERROR] JENKINS_MATTERMOST_WEBHOOK not found in cicd.env."
    echo "       Please run 04-configure-integrations.py first."
    exit 1
fi

if [ ! -f "$JENKINS_ENV_FILE" ]; then
    echo "[ERROR] Jenkins env file not found at: $JENKINS_ENV_FILE"
    exit 1
fi

echo "[INFO] Injecting Mattermost Webhook into jenkins.env..."

# Idempotency check using grep
if ! grep -q "MATTERMOST_JENKINS_WEBHOOK_URL" "$JENKINS_ENV_FILE"; then
cat << EOF >> "$JENKINS_ENV_FILE"

# --- Mattermost Integration ---
MATTERMOST_JENKINS_WEBHOOK_URL=$JENKINS_MATTERMOST_WEBHOOK
EOF
    echo "[INFO] Secrets injected."
else
    echo "[INFO] Secrets already present."
fi

# --- 2. Update JCasC ---
echo "[INFO] Updating JCasC configuration..."
if [ ! -f "$PY_HELPER" ]; then
    echo "[ERROR] Python helper script not found at $PY_HELPER"
    exit 1
fi

# Install yaml if missing (on host)
if ! python3 -c "import yaml" 2>/dev/null; then
    sudo apt-get update -qq && sudo apt-get install -y -qq python3-yaml
fi

python3 "$PY_HELPER"

# --- 3. Re-Deploy Jenkins ---
echo "[INFO] Triggering Jenkins Re-deployment..."

if [ ! -x "$DEPLOY_SCRIPT" ]; then
    echo "[ERROR] Deploy script not found: $DEPLOY_SCRIPT"
    exit 1
fi

(cd "$JENKINS_MODULE_DIR" && ./03-deploy-controller.sh)

echo "[SUCCESS] Jenkins is restarting with Mattermost integration."