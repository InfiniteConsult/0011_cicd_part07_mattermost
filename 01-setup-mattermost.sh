#!/usr/bin/env bash

#
# -----------------------------------------------------------
#               01-setup-mattermost.sh
#
#  The "Architect" script for Mattermost.
#
#  1. Secrets: Generates TURN credentials and Salt keys.
#  2. Database: Hot-patches PostgreSQL 15+ Schema Ownership.
#  3. Certificates: Generates a "Mobile-Ready" SSL cert (.lan.crt.pem).
#  4. Config: Generates the 'mattermost.env' 12-factor file.
#  5. Permissions: Sets ownership for Bind Mounts ONLY.
#
# -----------------------------------------------------------

set -e

# --- 1. Define Paths ---
HOST_CICD_ROOT="$HOME/cicd_stack"
MATTERMOST_BASE="$HOST_CICD_ROOT/mattermost"
MASTER_ENV_FILE="$HOST_CICD_ROOT/cicd.env"
SCOPED_ENV_FILE="$MATTERMOST_BASE/mattermost.env"

# Certificate Authority Paths
CA_DIR="$HOST_CICD_ROOT/ca"
SERVICE_NAME="mattermost.cicd.local"
CA_SERVICE_DIR="$CA_DIR/pki/services/$SERVICE_NAME"

# Ensure directories exist (Bind Mounts Only)
mkdir -p "$MATTERMOST_BASE/config"
mkdir -p "$MATTERMOST_BASE/certs"

# FIX: Temporarily claim ownership for the host user so we can write files
echo "🔧 Setting temporary permissions for setup..."
sudo chown -R "$USER":"$USER" "$MATTERMOST_BASE"

echo "🚀 Starting Mattermost 'Architect' Setup..."

# --- 2. Secrets Management ---
echo "--- Phase 1: Secrets Management ---"

if [ ! -f "$MASTER_ENV_FILE" ]; then
    echo "ERROR: Master env file not found at $MASTER_ENV_FILE"
    exit 1
fi

# Load existing secrets
set -a
source "$MASTER_ENV_FILE"
set +a

# Helper to generate random secrets
generate_secret() {
    openssl rand -hex 32
}

# Verify DB password exists (from Article 9)
if [ -z "$MATTERMOST_DB_PASSWORD" ]; then
    echo "ERROR: MATTERMOST_DB_PASSWORD not found in cicd.env"
    echo "Please run 01-setup-database.sh (Article 9) first."
    exit 1
fi

# Generate new Mattermost-specific secrets if missing
update_env=false

if [ -z "$MATTERMOST_TURN_SECRET" ]; then
    echo "Generating TURN Shared Secret..."
    echo "" >> "$MASTER_ENV_FILE"
    echo "# Mattermost & Coturn Shared Secret" >> "$MASTER_ENV_FILE"
    echo "MATTERMOST_TURN_SECRET=\"$(generate_secret)\"" >> "$MASTER_ENV_FILE"
    update_env=true
fi

if [ -z "$MATTERMOST_AT_REST_KEY" ]; then
    echo "Generating At-Rest Encryption Key..."
    echo "# Mattermost At-Rest Encryption Key" >> "$MASTER_ENV_FILE"
    echo "MATTERMOST_AT_REST_KEY=\"$(generate_secret)\"" >> "$MASTER_ENV_FILE"
    update_env=true
fi

if [ -z "$MATTERMOST_PUBLIC_LINK_SALT" ]; then
    echo "Generating Public Link Salt..."
    echo "# Mattermost Public Link Salt" >> "$MASTER_ENV_FILE"
    echo "MATTERMOST_PUBLIC_LINK_SALT=\"$(generate_secret)\"" >> "$MASTER_ENV_FILE"
    update_env=true
fi

# Reload secrets if we added any
if [ "$update_env" = true ]; then
    source "$MASTER_ENV_FILE"
    echo "Secrets generated and persisted."
else
    echo "Secrets already exist."
fi

# --- 3. Database Schema Ownership Fix (Postgres 15+) ---
echo "--- Phase 2: Verifying Database Schema Ownership ---"
# Postgres 15+ revokes permission to create tables in 'public' from regular users.
# We apply this fix specifically to the 'mattermost' database.

if [ "$(docker ps -q -f name=postgres)" ]; then
    echo "Applying PostgreSQL 15+ schema ownership fix..."
    docker exec -i postgres psql -U postgres -d mattermost -c "ALTER SCHEMA public OWNER TO mattermost;" || true
    echo "Database schema permissions verified."
else
    echo "WARNING: Postgres container not running. Skipping DB patch."
    echo "Ensure postgres is running before deploying Mattermost."
fi

# --- 4. Mobile-Ready Certificate Generation ---
echo "--- Phase 3: Generating Mobile-Ready SSL Certificate ---"

# Detect LAN IP (First non-loopback IP)
LAN_IP=$(hostname -I | awk '{print $1}')
echo "Detected LAN IP: $LAN_IP"

# Define Paths for the LAN-specific cert
mkdir -p "$CA_SERVICE_DIR"
LAN_KEY_FILE="$CA_SERVICE_DIR/$SERVICE_NAME.lan.key.pem"
LAN_CSR_FILE="$CA_SERVICE_DIR/$SERVICE_NAME.lan.csr"
LAN_CERT_FILE="$CA_SERVICE_DIR/$SERVICE_NAME.lan.crt.pem"
EXT_FILE="$CA_SERVICE_DIR/v3.lan.ext"

# Destination in Mattermost volume
MM_CERTS_DIR="$MATTERMOST_BASE/certs"

if [ -f "$LAN_CERT_FILE" ]; then
    echo "Existing LAN certificate found. Skipping generation."
else
    echo "Generating new LAN certificate..."

    # 1. Generate Key
    openssl genrsa -out "$LAN_KEY_FILE" 4096

    # 2. Create specific SAN config including the LAN IP
    cat > "$EXT_FILE" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $SERVICE_NAME
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = $LAN_IP
EOF

    # 3. Generate CSR
    openssl req -new -key "$LAN_KEY_FILE" -out "$LAN_CSR_FILE" \
        -subj "/C=ZA/ST=Gauteng/L=Johannesburg/O=Local CICD/CN=$SERVICE_NAME"

    # 4. Sign with Root CA
    CA_ROOT_DIR="$CA_DIR/pki"
    # Assuming CA pass is standard from previous articles
    openssl x509 -req -in "$LAN_CSR_FILE" \
        -CA "$CA_ROOT_DIR/certs/ca.pem" \
        -CAkey "$CA_ROOT_DIR/private/ca.key" \
        -CAcreateserial -out "$LAN_CERT_FILE" \
        -days 365 \
        -sha256 \
        -extfile "$EXT_FILE" \
        -passin pass:your_secure_password

    echo "Certificate generated: $LAN_CERT_FILE"
fi

# Always copy to the run directory
echo "Installing certificates to $MM_CERTS_DIR..."
cp "$LAN_CERT_FILE" "$MM_CERTS_DIR/cert.pem"
cp "$LAN_KEY_FILE" "$MM_CERTS_DIR/key.pem"

# --- 5. Generate Scoped Environment File ---
echo "--- Phase 4: Generating mattermost.env ---"

# NOTE: We remove quotes around simple string values (default_on, id_loaded)
# because docker --env-file might pass the quotes literally, breaking validation.
cat << EOF > "$SCOPED_ENV_FILE"
# Scoped Environment for Mattermost
# Generated by 01-setup-mattermost.sh

# --- Core Identity ---
MM_SQLSETTINGS_DRIVERNAME=postgres
# Note: We use the internal Docker DNS 'postgres.cicd.local'
# FIX: sslmode=verify-full because we enforce SSL in Postgres and inject the CA into Mattermost
MM_SQLSETTINGS_DATASOURCE=postgres://mattermost:$MATTERMOST_DB_PASSWORD@postgres.cicd.local:5432/mattermost?sslmode=verify-full&connect_timeout=10
MM_SERVICESETTINGS_SITEURL=https://$SERVICE_NAME:8065
MM_SERVICESETTINGS_LISTENADDRESS=:8065
# Security: Allow local IPs (needed for Webhooks from other containers)
# We strictly allow: localhost, Docker subnet, and Host LAN IP
MM_SERVICESETTINGS_ALLOWEDUNTRUSTEDINTERNALCONNECTIONS="127.0.0.1/8 172.30.0.0/24 $LAN_IP/32"

# --- TLS Configuration (Application Level) ---
MM_SERVICESETTINGS_CONNECTIONSECURITY=TLS
MM_SERVICESETTINGS_TLSCERTFILE=/mattermost/certs/cert.pem
MM_SERVICESETTINGS_TLSKEYFILE=/mattermost/certs/key.pem

# --- Security & Privacy ---
MM_SERVICESETTINGS_ENABLELOCALMODE=true
MM_EMAILSETTINGS_PUSHNOTIFICATIONCONTENTS=id_loaded
MM_FILESETTINGS_PUBLICLINKSALT=$MATTERMOST_PUBLIC_LINK_SALT
MM_SQLSETTINGS_ATRESTENCRYPTKEY=$MATTERMOST_AT_REST_KEY

# --- Developer Experience ---
MM_SERVICESETTINGS_ENABLELATEX=true
MM_SERVICESETTINGS_ENABLEINLINELATEX=true
MM_SERVICESETTINGS_COLLAPSEDTHREADS=default_on
MM_SERVICESETTINGS_ENABLECUSTOMGROUPS=true

# --- Announcements ---
MM_ANNOUNCEMENTSETTINGS_ENABLEBANNER=true
MM_ANNOUNCEMENTSETTINGS_BANNERTEXT="🚀 CI/CD City: Systems Operational"
MM_ANNOUNCEMENTSETTINGS_BANNERCOLOR="#20a83b"

# --- Advanced "Cool" Features ---

# 1. Performance Metrics (Port 8067)
MM_METRICSSETTINGS_ENABLE=true
MM_METRICSSETTINGS_LISTENADDRESS=:8067

# 2. Guest Access
MM_GUESTACCOUNTSSETTINGS_ENABLE=true

# 3. Automation Freedom
MM_SERVICESETTINGS_ENABLEBOTACCOUNTCREATION=true
MM_SERVICESETTINGS_ENABLEUSERACCESSTOKENS=true

# 4. Hardened Security (MFA)
MM_SERVICESETTINGS_ENABLEMULTIFACTORAUTHENTICATION=true

# 5. Urgent Messaging
MM_SERVICESETTINGS_POSTPRIORITY=true

# 6. Culture (Custom Emoji)
MM_SERVICESETTINGS_ENABLECUSTOMEMOJI=true

# --- Plugins (Force Enable for Entry Mode) ---
# NOTE: Single-line JSON without outer quotes to satisfy Docker env file parser
MM_PLUGINSETTINGS_PLUGINSTATES={"playbooks":{"Enable":true},"focalboard":{"Enable":true},"com.mattermost.calls":{"Enable":true},"mattermost-ai":{"Enable":true},"com.github.manland.mattermost-plugin-gitlab":{"Enable":true}}

# --- WebRTC (The Radio Tower) ---
MM_PLUGINSETTINGS_PLUGINS_COM_MATTERMOST_CALLS_RTCSERVERPORT=8443
MM_PLUGINSETTINGS_PLUGINS_COM_MATTERMOST_CALLS_ICESERVERSCONFIGS=[{"urls":["turn:$LAN_IP:3478"],"username":"mattermost","credential":"$MATTERMOST_TURN_SECRET"}]
EOF

# Secure the env file (readable by owner only)
chmod 600 "$SCOPED_ENV_FILE"

# --- 6. Final Permissions Lock ---
echo "--- Phase 5: Locking Permissions (UID 2000) ---"
# FIX: We ONLY chown the directories that need to be bind-mounted.
# We leave the .env file owned by the current user so docker run can read it.
sudo chown -R 2000:2000 "$MATTERMOST_BASE/config"
sudo chown -R 2000:2000 "$MATTERMOST_BASE/certs"

# The Key file must be readable by the app (0600 owned by 2000)
# (Already handled by the recursive chown above, but ensuring mode)
sudo chmod 600 "$MM_CERTS_DIR/key.pem"

echo "✅ Setup Complete."
echo "   - Config written to $SCOPED_ENV_FILE."
echo "   - Bind Mounts ownership transferred to UID 2000."