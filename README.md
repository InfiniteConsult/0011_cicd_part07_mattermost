# Chapter 1: The Challenge - The Silent City

## 1.1 The "Lights Out" Problem

In the previous six articles, we have meticulously constructed a sovereign "Software Supply Chain." We started with the foundation in **Docker** and a custom **Certificate Authority**, then built a **Library** (GitLab) to store our blueprints, a **Factory** (Jenkins) to manufacture our products, an **Inspector** (SonarQube) to certify their quality, and a **Warehouse** (Artifactory) to store them securely.

Technically, our city is perfect. The pipelines run, the code is analyzed, and the artifacts are shipped.

But functionally, our city is broken. It is a "Silent City."

When a build fails in the Factory, the only person who knows is the engineer staring at the Jenkins console. When the Inspector slams the Quality Gate shut, the event is logged in a database, but no alarm bells ring. To know the status of our operations, we are forced to manually patrol the dashboards of four different tools. We have built a complex machine, but we have failed to build a nervous system.

In a modern DevOps environment, this latency is unacceptable. We need instantaneous, passive awareness. If the "Main Line" stops, every engineer should know immediately. If a critical security vulnerability is detected, the alert should find us where we are—whether that is at our desk or on our phone.

## 1.2 The "Command Center" (ChatOps)

To solve this, we need to fundamentally change how we interact with our infrastructure. We need to move beyond passive monitoring and fragmented dashboards. We need a **Command Center**.

This concept is industry-known as **ChatOps**. It represents a paradigm shift where the chat client ceases to be merely a "water cooler" for human conversation and becomes a shared, real-time command line interface for the entire engineering team. In a mature ChatOps environment, the chat window is the central console where operations happen. You don't alt-tab to Jenkins to trigger a build; you type `/jenkins build` in the channel. You don't log into SonarQube to check the quality gate; the gate reports its status directly to you.

By centralizing these operations, we achieve three critical goals:
1.  **Transparency:** Every action is visible to the team. If a senior engineer fixes a broken build, the junior engineers watch it happen in real-time, learning the diagnosis and the cure implicitly.
2.  **Context:** The alert is located right next to the conversation about the alert. The "What happened?" and the "Why did it happen?" live in the same timeline.
3.  **Velocity:** We reduce context switching. We stop jumping between four different browser tabs to understand the state of the world.

In a typical startup environment, setting this up is trivial: you sign up for Slack or Discord, generate a webhook token, and pipe your logs to the cloud. However, our "First Principles" architecture strictly forbids this. We are simulating a high-assurance, air-gapped environment—modeled after defense or financial sectors—where data sovereignty is paramount.

We cannot pipe our proprietary build logs, code snippets, or vulnerability reports to a third-party SaaS cloud. That data constitutes our intellectual property and our security posture. If we use Slack, our internal state leaves our perimeter.

Therefore, we will deploy **Mattermost**. Mattermost is the open-source industry standard for secure, self-hosted collaboration. It offers the modern features we expect—threaded messaging, file sharing, rich media, and mobile applications—but it runs entirely on our own silicon, inside our `cicd-net`. It gives us the usability of Silicon Valley SaaS with the security of a hardened bunker.

## 1.3 The Scope: War Room & Nervous System

However, a "Command Center" is defined by more than just its ability to display text. In the heat of a production incident or a broken build pipeline, text is often the bottleneck.

When the "Main Line" stops, the immediate next step is almost always a "War Room" scenario. Engineers need to escalate from asynchronous text to synchronous collaboration. They need to see each other, share screens, point at logs, and debug the issue in real-time. In a traditional setup, this is the moment the team breaks protocol: they leave the secure chat, open Zoom or Microsoft Teams, and effectively carry the conversation (and potentially sensitive screen data) out of the secure facility and onto a public cloud server.

This breaks our security model. It punches a hole in our air-gapped fortress. To maintain total sovereignty, we must provide a Video Conferencing capability that is as secure and local as the code itself.

So, our mission in this article is twofold:

1.  **The Nervous System:** We will wire up the sensory organs of our city—Jenkins, GitLab, and SonarQube—to push rich, actionable alerts into specific Mattermost channels (`#builds`, `#alerts`).
2.  **The War Room:** We will deploy a fully functional, self-hosted Video Conferencing stack using the Mattermost **Calls** plugin.

This second requirement will force us to confront one of the most notorious "Dragons" in self-hosted networking: **NAT Traversal**. Unlike simple HTTP traffic, which flows easily through Docker containers, real-time video relies on **WebRTC** (Web Real-Time Communication). This protocol is allergic to the complex layers of Network Address Translation (NAT) found in Docker. To make this work—specifically to make it work on a mobile phone over WiFi—we will have to build a dedicated "Radio Tower" (TURN Server) to relay the signal over the walls of our container fortress.

# Chapter 2: Architecture - The Fortress and the Phone

## 2.1 The "Enterprise" Hack (Entry Mode)

Our first architectural decision concerns the software edition. Mattermost offers two primary Docker images: the purely open-source **Team Edition** (`mattermost-team-edition`) and the commercial **Enterprise Edition** (`mattermost-enterprise-edition`).

Historically, self-hosters strictly deployed the Team Edition to avoid licensing nags. However, Mattermost has shifted its distribution model. They now encourage even free users to deploy the **Enterprise Image**. When deployed without a license key, this image runs in a special state known as **"Entry Mode."**

We will adopt this modern approach.

We choose the Enterprise image not because we intend to pirate software, but because the Team Edition is functionally incomplete for a modern DevOps workflow. By running the Enterprise image in Entry Mode, we unlock the **"Intelligent Mission Environment."** This grants us access to powerful tools like **Boards** (Kanban project management) and **Playbooks** (incident response checklists)—features that are entirely stripped from the Team build.

This power comes with constraints. Entry Mode imposes hard limits designed to encourage commercial upgrades:
* **10,000 Message Search Limit:** Older messages remain in the database but vanish from search results.
* **Single Node Only:** We cannot cluster the application for High Availability.
* **Feature Caps:** Limits on active Playbooks and Board cards.

For our "First Principles" laboratory, these limits are acceptable. For a production client, we would strongly advise purchasing a license to lift these gates. But for us, this strategy gives us Ferrari features on a Corolla budget.

Finally, we will treat our database as a commodity. In **Article 9**, we established a centralized **PostgreSQL 17** cluster. Mattermost will not spawn its own private database container; it will simply be another tenant in our existing "Water Treatment Plant," connecting via our internal `cicd-net`. This reduces our resource footprint and ensures our chat data benefits from the same backup and security policies as our artifact data.

## 2.2 The "Mobile-Ready" Trust

The second architectural challenge is **Trust**, specifically how trust varies across different devices in our ecosystem.

In previous articles, we established a "Local Root of Trust" using our custom Certificate Authority (CA). On our desktop machines, this system works flawlessly. We imported our Root CA into the operating system's trust store (Debian/Ubuntu/MacOS), and our browsers immediately recognized `gitlab.cicd.local` and `jenkins.cicd.local` as secure. We relied on a simple `/etc/hosts` modification to route those domain names to `127.0.0.1`, effectively tricking the browser into believing the server was local.

However, our Command Center has a requirement that our other tools did not: **Mobile Access**. We want to receive alerts and join "War Room" calls from our Android or iOS devices while roaming around the office (connected to WiFi).

This introduces a hostile environment. Mobile operating systems, particularly modern Android (11+), are notoriously strict about TLS security. They present two specific barriers that break our standard desktop strategy:

1.  **The DNS Barrier:** You cannot easily edit the `/etc/hosts` file on a non-rooted Android phone. This means the phone has no idea who `mattermost.cicd.local` is. It relies entirely on the network's DNS server. Unless we run a custom DNS server on our LAN (like Pi-hole), the phone will fail to resolve the domain name.
2.  **The IP Barrier:** To bypass the DNS issue, we might try to connect directly via the server's LAN IP address (e.g., `https://192.168.0.105:8065`). However, standard SSL certificates are issued to *Domain Names*, not *IP Addresses*. If we use our standard certificate, the app will reject the connection because the "Common Name" (domain) does not match the "Host" (IP) in the address bar.
3.  **The Trust Barrier:** Even if the IP matches, the Android app does not trust our custom CA by default. It will throw a generic, often cryptic error like "Trusted Anchor not found" or simply "Cannot connect to server."

To solve this, we must engineer a **"Mobile-Ready" Certificate**. We cannot use the generic certificate generation script we built in Article 6. We need a specialized issuance process that explicitly bakes the **LAN IP Address** into the certificate's **Subject Alternative Names (SANs)** field.

By adding `IP:192.168.x.x` to the certificate, we create a cryptographic identity that is valid even when accessed via a raw IP address. This allows us to bypass the DNS problem entirely. We simply tell the mobile app to connect to the IP, and because the certificate explicitly claims that IP, the TLS handshake succeeds—provided we also manually install the Root CA on the device (which we will cover in the deployment phase). This architectural foresight turns a "connection refused" error into a functioning mobile command post.

## 2.3 The "Radio Tower" (Coturn & Host Networking)

The final and most formidable piece of our architecture is the **Video Conferencing** stack. This requirement forces us to leave the comfortable world of HTTP and confront the chaotic reality of **WebRTC** (Web Real-Time Communication).

In our previous articles, every service we deployed—GitLab, Jenkins, SonarQube—communicated using TCP/IP over HTTP. This model is simple: the client opens a connection to the server, sends a request, and waits for a response. It is reliable, predictable, and remarkably tolerant of network layers like Docker's bridge network and Nginx reverse proxies.

**WebRTC is different.** It is designed for real-time audio and video, where latency is the enemy. It prefers **UDP** over TCP because it's faster to drop a lost packet than to wait for retransmission (a glitch is better than a lag). More importantly, WebRTC attempts to establish a **Peer-to-Peer (P2P)** connection directly between two devices to minimize latency.

In a containerized environment, this P2P model breaks instantly.

When your phone (on WiFi) tries to send video to the Mattermost server (in a container), it needs an IP address to target. However, the Mattermost container lives inside a Docker Bridge network. It has an internal IP (e.g., `172.18.0.5`) that is completely invisible to the outside world. To make matters worse, your phone is likely behind its own NAT (Network Address Translation). This scenario is known as **Double NAT**, and it acts as an unbridgeable moat for direct media streams.

To bridge this moat, we need a **TURN Server** (Traversal Using Relays around NAT). We will deploy **Coturn**, the industry-standard open-source TURN server.

Architecturally, Coturn acts as a **"Radio Tower."** It sits on the absolute edge of our network. When direct P2P communication fails (which it always will in Docker), the phone sends its media packets to the Radio Tower. The Tower then relays those packets across the Docker boundary to the Mattermost container.

But deploying Coturn brings its own "Dragon": **The Port Range.**

Unlike a web server that listens on a single port (443), a TURN server requires a massive range of ephemeral UDP ports—typically **32,768 to 65,535**—to handle media streams for multiple users simultaneously. Every active call consumes a port.

If we tried to deploy this using standard Docker Bridge networking, we would have to map every single one of these ports in the `docker run` command or Compose file. This creates two critical problems:
1.  **The "Docker Proxy" Bottleneck:** For every mapped port, Docker spins up a userland proxy process (`docker-proxy`). Asking Docker to manage 30,000+ proxy rules explodes the memory usage and adds significant CPU latency to every packet, killing call quality.
2.  **IPTables Bloat:** Creating tens of thousands of NAT rules in the host's firewall table slows down networking for the entire system.

To solve this, we will make a rare exception to our "Isolation First" rule. We will deploy the Coturn container using **Host Networking** (`--network host`).

This mode effectively removes the Docker network isolation layer for this specific container. Coturn will not have a private `172.x.x.x` IP; it will bind directly to the physical network interface of your host machine (`192.168.x.x`). This eliminates the need for port mapping entirely. It gives our Radio Tower a clear, unobstructed line of sight to your mobile device, ensuring that when you press "Join Call," the video flows instantly and efficiently.

# Chapter 3: The Architect - Preparing the Ground

## 3.1 Database Hygiene (Postgres 15+ Compliance)

Before we write a single line of configuration code, we must attend to the soil in which we are planting our application. We are using **PostgreSQL 17** as our shared data store. While this gives us performance and longevity, it also brings strict security defaults that can strangle legacy applications if we aren't careful.

Specifically, PostgreSQL 15 introduced a breaking change regarding schema ownership. In older versions, any user could create tables in the `public` schema by default. In 15+, this permission was revoked to harden the database against accidental pollution.

Mattermost, like many mature applications, expects to own its schema completely. It performs complex migrations on startup—creating tables, altering columns, and indexing data. If the database user (`mattermost`) does not explicitly own the `public` schema, these migrations can fail. Often, this failure is silent or cryptic, manifesting as a boot loop where the logs complain about "permission denied" on a table that doesn't exist yet.

To prevent this "Silent Crash," we cannot just create the user and hope for the best. Our setup script must actively intervene. We will use the `psql` client to execute a targeted `ALTER SCHEMA` command, explicitly transferring ownership of the `public` schema in the `mattermost` database to the `mattermost` user. This restores the "God Mode" permissions the application expects within its own sandbox, ensuring smooth migrations for years to come.

## 3.2 The "Mobile-Ready" Certificate

With our database secured, we must address the single biggest friction point in self-hosted DevOps: **Mobile Trust**.

In our previous articles, we connected our desktop browsers to our internal tools using a simple trick. We updated our `/etc/hosts` file to map `gitlab.cicd.local` to `127.0.0.1`. Because we had imported our Root CA into the desktop's trust store, the browser saw a valid certificate for a valid domain and gave us the green lock.

Mobile devices, however, exist in a more hostile networking environment.

Modern Android (11+) and iOS devices lock down their DNS settings. You cannot simply edit a "hosts file" on a non-rooted phone to tell it that `mattermost.cicd.local` resides on your laptop. When your phone is on the office WiFi, it uses the router's DNS. If that router doesn't know your internal domain (which it won't, because we don't have a custom DNS server like Pi-hole), the phone will fail to resolve the address.

The pragmatic workaround is to bypass DNS entirely and connect via the **LAN IP Address** (e.g., `https://192.168.0.105:8065`).

This solves the network path, but it breaks the **TLS Identity Trust**. Standard SSL certificates are bound to **Domain Names** (DNS entries). If you present a certificate issued to `mattermost.cicd.local` but the user is visiting `192.168.0.105`, the client will reject the connection immediately because the "Host" does not match the "Certificate Name." This is a fundamental protection against Phishing and Man-in-the-Middle attacks.

To conquer this, we must engineer a **"Mobile-Ready" Certificate**.

We cannot use the generic issuance script we built in Article 6. We need a specialized signing request that explicitly creates a **Subject Alternative Name (SAN)** entry for the IP address. By baking `IP:192.168.x.x` directly into the certificate's cryptographic identity, we tell the mobile OS: *"It is legal and valid for this server to be accessed via this raw IP address."*

Our architect script will automate this. It will dynamically detect your host's LAN IP (`hostname -I`), construct a custom OpenSSL configuration file with the required SAN extensions, and mint a certificate that satisfies the strict identity requirements of modern mobile operating systems.

## 3.3 Secrets Management

Beyond certificates and database permissions, a secure Mattermost deployment relies on a specific set of cryptographic keys. These are not simple passwords that you can type in; they are high-entropy strings that underpin the security of the application's data at rest and in transit.

If we leave these default or empty, we compromise the integrity of our fortress. Our Architect script manages three critical secrets:

1.  **The At-Rest Encryption Key (`MM_SQLSETTINGS_ATRESTENCRYPTKEY`):**
    Mattermost stores sensitive data in the Postgres database, including OAuth tokens for GitLab and incoming webhook secrets for Jenkins. If an attacker managed to dump our database, these tokens would be exposed in plain text. By configuring an At-Rest Encryption Key (32-character AES), we ensure that Mattermost encrypts these sensitive fields before writing them to the disk.

2.  **The Public Link Salt (`MM_FILESETTINGS_PUBLICLINKSALT`):**
    When a user shares a file via a public link, the URL is generated using a hash function. Without a strong, random salt, these links become predictable, potentially allowing an external attacker to enumerate and download private files by guessing URL patterns.

3.  **The TURN Shared Secret (`MATTERMOST_TURN_SECRET`):**
    This is the most critical key for our "War Room" functionality. The Coturn (Radio Tower) server and the Mattermost (Town Square) server are separate entities. To prevent unauthorized users from hijacking our bandwidth to relay their own traffic, the TURN server requires authentication.
    We do not use a static username/password for this. Instead, we use a **Time-Limited Credential** mechanism. Both servers share this single, long secret key. Mattermost uses it to generate temporary, short-lived tokens for your phone when you join a call. Coturn uses the same key to validate those tokens. If these keys do not match exactly, the call fails instantly.

Our script uses `openssl rand -hex` to generate these strings. Crucially, as we discovered during our GitLab integration debugging (Chapter 9), we must be precise about length. For AES-256 encryption, the key must be exactly **32 bytes**. A 64-byte key (often generated by overzealous `openssl` commands) will cause the application's crypto subsystem to crash on boot.

We persist these keys in our master `cicd.env` file, ensuring that our "Radio Tower" and our "Town Square" always wake up knowing the same handshake.

## 3.4 The Script (`01-setup-mattermost.sh`)

We have defined our requirements: Postgres 15+ hygiene, mobile-ready networking, and cryptographic security. Now, we codify these rules into our "Architect" script.

This script is the single source of truth for the Mattermost deployment. It does not launch the container; it prepares the battlefield. It ensures that when the container finally starts, it lands in an environment that is secure, configured, and trusted.

Create this file at `~/Documents/FromFirstPrinciples/articles/0011_cicd_part07_mattermost/01-setup-mattermost.sh`.

```bash
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

# Helper: Generates 64-char string (Good for Salts/Secrets)
generate_secret() {
    openssl rand -hex 32
}

# Helper: Generates 32-char string (REQUIRED for AES Encryption Keys)
generate_aes_key() {
    openssl rand -hex 16
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
    echo "Generating At-Rest Encryption Key (Core)..."
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

# Plugin Secrets (GitLab/Jenkins Interactive)
if [ -z "$MATTERMOST_GITLAB_PLUGIN_SECRET" ]; then
    echo "Generating GitLab Plugin Webhook Secret..."
    echo "MATTERMOST_GITLAB_PLUGIN_SECRET=\"$(generate_secret)\"" >> "$MASTER_ENV_FILE"
    update_env=true
fi

if [ -z "$MATTERMOST_GITLAB_PLUGIN_KEY" ]; then
    echo "Generating GitLab Plugin Encryption Key (AES-256)..."
    # FIX: Must be exactly 32 chars
    echo "MATTERMOST_GITLAB_PLUGIN_KEY=\"$(generate_aes_key)\"" >> "$MASTER_ENV_FILE"
    update_env=true
fi

if [ -z "$MATTERMOST_JENKINS_PLUGIN_KEY" ]; then
    echo "Generating Jenkins Plugin Encryption Key (AES-256)..."
    # FIX: Must be exactly 32 chars
    echo "MATTERMOST_JENKINS_PLUGIN_KEY=\"$(generate_aes_key)\"" >> "$MASTER_ENV_FILE"
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
# NOTE: We only enable them here. Specific config is handled by 08-configure-plugins.py
# Added: com.mattermost.plugin-jenkins
MM_PLUGINSETTINGS_PLUGINSTATES={"playbooks":{"Enable":true},"focalboard":{"Enable":true},"com.mattermost.calls":{"Enable":true},"mattermost-ai":{"Enable":true},"com.github.manland.mattermost-plugin-gitlab":{"Enable":true},"jenkins":{"Enable":true}}

# --- WebRTC (The Radio Tower) ---
# 1. Connectivity (Moved to 8444 to avoid conflict with Artifactory on 8443)
MM_CALLS_UDP_SERVER_PORT=8444
MM_CALLS_TCP_SERVER_PORT=8444
MM_CALLS_ICE_SERVERS_CONFIGS=[{"urls":["turn:$LAN_IP:3478"],"username":"mattermost","credential":"$MATTERMOST_TURN_SECRET"}]

# 2. Network Stability
MM_CALLS_ICE_HOST_OVERRIDE=$LAN_IP

# 3. User Permissions
MM_CALLS_DEFAULT_ENABLED=true

# 4. Features
MM_CALLS_ALLOW_SCREEN_SHARING=true
MM_CALLS_ICE_HOST_PORT_OVERRIDE=8444

# 5. Mobile & CORS Fixes
MM_SERVICESETTINGS_ALLOWCORSFROM=*
MM_SERVICESETTINGS_ENABLEINSECUREOUTGOINGCONNECTIONS=true
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
```

### Deconstructing the Architect

**1. The "Split-Brain" Certificate Strategy (Phase 3)**
Notice the `[alt_names]` block. We explicitly define `IP.2 = $LAN_IP`. This dynamic injection is what makes the certificate "Mobile-Ready." Unlike our standard scripts which only care about the DNS name (`mattermost.cicd.local`), this script queries the host's actual network interface (`hostname -I`) and bakes that physical address into the cryptographic identity. This ensures that when an Android phone connects to `192.168.0.x`, the certificate matches the URL.

**2. The Key Length Fix (Phase 1)**
We use two different generator functions: `generate_secret` (64 hex chars) and `generate_aes_key` (16 hex chars). This is a critical distinction. The At-Rest Encryption Key and Plugin Encryption Keys rely on AES-256. This algorithm strictly requires a **32-byte key**. If we used the standard 64-char generator (which results in 64 bytes when hex-encoded), the Mattermost server would crash on startup with a generic `invalid key size` error. We are precise here to prevent runtime failures.

**3. The WebRTC Configuration (Phase 4)**
In the environment file generation, we configure the **Calls** plugin immediately.

* `MM_CALLS_ICE_HOST_OVERRIDE=$LAN_IP`: This forces the server to advertise the LAN IP, not the internal Docker IP (`172.x`), ensuring the phone knows where to send the video packets.
* `MM_CALLS_UDP_SERVER_PORT=8444`: We shift the media port from the default (8443) to 8444. This avoids a collision with **Artifactory** (Article 9), which already claimed 8443 for its HTTPS interface. In a "City," port discipline is mandatory.

# Chapter 4: The Radio Tower - Deploying Coturn

## 4.1 The NAT Traversal Challenge

With our "Town Square" foundation laid, we must now build the infrastructure that allows us to see and hear each other. We are deploying the Video Conferencing stack using the Mattermost **Calls** plugin.

This requirement forces us to leave the comfortable world of HTTP and confront the chaotic reality of **WebRTC** (Web Real-Time Communication).

In our previous articles, every service we deployed—GitLab, Jenkins, SonarQube—communicated using TCP/IP over HTTP. This model is simple: the client opens a connection to the server, sends a request, and waits for a response. It is reliable, predictable, and remarkably tolerant of network layers like Docker's bridge network and Nginx reverse proxies.

**WebRTC is different.** It is designed for real-time audio and video, where latency is the enemy. It prefers **UDP** over TCP because it's faster to drop a lost packet than to wait for retransmission (a glitch is better than a lag). More importantly, WebRTC attempts to establish a **Peer-to-Peer (P2P)** connection directly between two devices to minimize latency.

In a containerized environment, this P2P model breaks instantly.

When your phone (on WiFi) tries to send video to the Mattermost server (in a container), it needs an IP address to target. However, the Mattermost container lives inside a Docker Bridge network. It has an internal IP (e.g., `172.18.0.5`) that is completely invisible to the outside world. To make matters worse, your phone is likely behind its own NAT (Network Address Translation). This scenario is known as **Double NAT**, and it acts as an unbridgeable moat for direct media streams.

To bridge this moat, we need a **TURN Server** (Traversal Using Relays around NAT). We will deploy **Coturn**, the industry-standard open-source TURN server.

Architecturally, Coturn acts as a **"Radio Tower."** It sits on the absolute edge of our network. When direct P2P communication fails (which it always will in Docker), the phone sends its media packets to the Radio Tower. The Tower then relays those packets across the Docker boundary to the Mattermost container.

## 4.2 The Solution (`02-deploy-coturn.sh`)

But deploying Coturn brings its own "Dragon": **The Port Range.**

Unlike a web server that listens on a single port (443), a TURN server requires a massive range of ephemeral UDP ports—typically **49,152 to 65,535**—to handle media streams for multiple users simultaneously. Every active call consumes a port.

If we tried to deploy this using standard Docker Bridge networking, we would have to map every single one of these ports in the `docker run` command. This creates two critical problems:

1.  **The "Docker Proxy" Bottleneck:** For every mapped port, Docker spins up a userland proxy process (`docker-proxy`). Asking Docker to manage 16,000+ proxy rules explodes the memory usage and adds significant CPU latency to every packet, killing call quality.
2.  **IPTables Bloat:** Creating tens of thousands of NAT rules in the host's firewall table slows down networking for the entire system.

To solve this, we will make a rare exception to our "Isolation First" rule. We will deploy the Coturn container using **Host Networking** (`--network host`).

This mode effectively removes the Docker network isolation layer for this specific container. Coturn will not have a private `172.x.x.x` IP; it will bind directly to the physical network interface of your host machine (`192.168.x.x`). This eliminates the need for port mapping entirely. It gives our Radio Tower a clear, unobstructed line of sight to your mobile device, ensuring that when you press "Join Call," the video flows instantly and efficiently.

Create this file at `~/Documents/FromFirstPrinciples/articles/0011_cicd_part07_mattermost/02-deploy-coturn.sh`.

```bash
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
```

### Deconstructing the Radio Tower

**1. The IP Detection (`hostname -I`)**
Coturn needs to know "who it is" to function correctly. When a phone asks for a relay candidate, Coturn must respond with an IP address that the phone can actually reach. We automate this by detecting the host's LAN IP at runtime and passing it to `--external-ip`. If we hardcoded this or let it default, Coturn might advertise an internal loopback address, causing call failures.

**2. The "No-Map" Deployment (`--network host`)**
Notice that there are no `-p 3478:3478` or `-p 49152:49152` flags in the `docker run` command. Because we used `--network host`, the container essentially "becomes" the host networking stack. It opens these sockets directly on the host's interface. This is the secret to high-performance WebRTC in Docker.

**3. The Shared Secret (`--static-auth-secret`)**
This ties back to **Article 3**. We inject the `MATTERMOST_TURN_SECRET`. This ensures that our Radio Tower isn't an open relay for the internet. It will only relay traffic for clients that present a valid token signed by our Mattermost server using this exact key.

## 4.3 The Verification (`test-turn-server.py`)

Before we try to connect a complex application like Mattermost to this Radio Tower, we must verify that the Tower is actually broadcasting. If we skip this step, debugging broken video calls later becomes a guessing game: is it the Android app? The certificate? The firewall? Or the TURN server itself?

We will perform a "Smoke Test" using the industry-standard **Trickle ICE** diagnostic tool.

To do this securely, we cannot just guess a username and password. Our TURN server is protected by the Time-Limited Credential mechanism. We need to generate a valid, signed token that expires in 24 hours.

We will write a small Python script to generate these credentials using the `MATTERMOST_TURN_SECRET` from our environment file.

Create this file at `~/Documents/FromFirstPrinciples/articles/0011_cicd_part07_mattermost/test-turn-server.py`.

```python
# https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/
import hashlib, hmac, base64, time
from pathlib import Path

# Load Secret
env_path = Path.home() / "cicd_stack" / "cicd.env"
secret = ""
with open(env_path) as f:
    for line in f:
        if "MATTERMOST_TURN_SECRET" in line:
            secret = line.split("=")[1].strip().strip("\"")

if not secret:
    print("Error: Could not find secret")
    exit(1)

# Generate Credentials (valid for 24 hours)
timestamp = int(time.time()) + (24 * 3600)
username = f"{timestamp}:testuser"
dig = hmac.new(secret.encode(), username.encode(), hashlib.sha1).digest()
password = base64.b64encode(dig).decode()

print("\n=== TURN Credentials (Valid 24h) ===")
print(f"Username: {username}")
print(f"Password: {password}")
print("====================================")
```

### Deconstructing the Smoke Test

This script implements the standard TURN REST API hashing algorithm. It combines a timestamp (valid for 24 hours) with a username, signs it with our secret key using HMAC-SHA1, and Base64 encodes the result. This matches exactly what the Mattermost server does internally when a user requests to join a call.

### Execution: The Trickle ICE Test

Now, we perform the physical test.

1.  **Generate Credentials:** Run the script on your host.

    ```bash
    python3 test-turn-server.py
    ```

    Copy the **Username** and **Password** output.

2.  **Open the Diagnostics Tool:**
    On a **different device** (like your phone or a laptop on the same WiFi, *not* the host running Docker), open this URL:
    [https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/](https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/)

3.  **Configure the Server:**

    * **STUN or TURN URI:** `turn:<YOUR_LAN_IP>:3478` (e.g., `turn:192.168.0.105:3478`)
    * **TURN username:** (Paste from script)
    * **TURN password:** (Paste from script)

4.  **Run the Test:** Click **"Gather candidates"**.

**The Success Criteria:**
You are looking for a specific row in the output table.

* **Component Type:** `rtcp` or `rtp`
* **Type:** **`relay`** (This is the critical keyword).
* **Protocol:** `udp`

If you see a candidate of type **`relay`**, it means your device successfully contacted the Coturn server, authenticated with the secret, and received a relay address. The Radio Tower is operational. If you only see `host` or `srflx` candidates, the TURN server is unreachable (check your firewall) or authentication failed (check your secret).


# Chapter 5: Deployment - Launching the Town Square

## 5.1 The "Clean Slate" Protocol

We have tuned our database, generated our mobile-ready certificates, and erected our radio tower. The ground is prepared. It is time to deploy the application itself.

We will use our standard **"Launcher"** pattern. This script (`03-deploy-mattermost.sh`) is the enforcement mechanism for our infrastructure. It does not just "start" the container; it ensures that every deployment begins with a predictable, clean state.

This "Clean Slate" protocol—stopping the container, removing it, and verifying volumes before launching—is critical for "Immutable Infrastructure." It guarantees that if we change a configuration variable in `mattermost.env` or update a certificate, the new container will pick up those changes immediately. We never rely on `docker restart`, which often preserves stale state.

This script also handles a specific architectural requirement for Mattermost: **Plugin Persistence**. Unlike Jenkins, where plugins are baked into the image or volume in a single blob, Mattermost benefits from separating its storage concerns. We create four distinct named volumes:

1.  `mattermost-data`: For file uploads and images.
2.  `mattermost-logs`: For audit trails (critical for security).
3.  `mattermost-plugins`: For server-side plugin binaries.
4.  `mattermost-client-plugins`: For the webapp frontend code of those plugins.

By separating these, we ensure that a plugin upgrade doesn't accidentally corrupt our file store, and that we can wipe plugins if necessary without losing user data.

Create this file at `~/Documents/FromFirstPrinciples/articles/0011_cicd_part07_mattermost/03-deploy-mattermost.sh`.

```bash
#!/usr/bin/env bash

#
# -----------------------------------------------------------
#               03-deploy-mattermost.sh
#
#  The "Town Square" script.
#  Deploys Mattermost Enterprise Edition (Entry Mode).
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
```

### Deconstructing the Launcher

**1. The Trust Injection (`/etc/ssl/certs/...`)**
This single line solves the "Island Problem" we faced with SonarQube and Jenkins. We mount the host's CA bundle directly over the container's CA bundle. Because we previously installed our Root CA on the host (Article 6), this "brain transplant" allows Mattermost to instantly trust `gitlab.cicd.local` and `jenkins.cicd.local`. Without this, every integration webhook would fail with a certificate error.

**2. The Port Strategy (`8444`)**
Notice we map port **8444** for both TCP and UDP. This corresponds to the `MM_CALLS_UDP_SERVER_PORT` setting we configured in the Architect script. By explicitly mapping this, we punch a hole through the Docker NAT for our relayed media packets coming from the Coturn server.

**3. The Image Selection (`enterprise-edition:release-11`)**
We explicitly pull the **Enterprise Edition**. As discussed in Chapter 2, this—combined with the lack of a license key—activates "Entry Mode," giving us access to Boards and Playbooks which are absent in the Team Edition image.

**4. The Localhost Bind (`127.0.0.1:8067`)**
For the metrics port, we bind strictly to `127.0.0.1`. We do not want our internal performance metrics exposed to the LAN. This allows a future Prometheus instance (running in the same `cicd-net`) to scrape metrics, or us to curl them from the host, but prevents casual snooping from the office WiFi.

# Chapter 6: The Mobile Frontier - Connecting Android

## 6.1 The "Generic Failure" Barrier

We have launched our "Town Square." From your desktop machine, you can likely open a browser, navigate to `https://mattermost.cicd.local:8065`, and see the login screen. The green lock icon is present because your desktop OS trusts the Root CA we installed in Article 6.

Now, we attempt to extend this perimeter to the mobile frontier.

Connect your Android device to the same WiFi network as your host machine. Open the official Mattermost app. Since we cannot easily configure DNS on a standard Android phone to resolve `.local` domains, we bypass the DNS system entirely and enter the raw IP address:

**Server URL:** `https://192.168.X.X:8065` (Replace with your LAN IP)

You will be met with an immediate, generic failure: **"Cannot connect to the server."**

This error message is dangerously misleading. It implies a network timeout or a firewall block. You might waste time checking `iptables` or Docker port mappings. However, the connection is physically reaching the server; it is being rejected at the cryptographic layer.

This is the "Trust Gap." Your Android device has its own segregated store of trusted Certificate Authorities (Google, DigiCert, Let's Encrypt). It has absolutely no knowledge of the "CICD-Root-CA" we generated on our laptop. When the server presents its "Mobile-Ready" certificate, the phone sees a valid cryptographic signature from an unknown entity. It assumes a Man-in-the-Middle attack is in progress and creates a hard stop at the TLS layer.

To fix this, we cannot just change a setting in the app. We must surgically intervene in the device's operating system.

## 6.2 The Manual Trust Protocol

To breach this barrier, we must perform a manual key exchange. We need to take the **Root CA** (`ca.pem`)—the "Master Key" that signed our Mattermost certificate—and import it into the Android "User Credentials" store. This explicitly tells the operating system: *"Trust any certificate signed by this file."*

This is a physical process that varies slightly by Android version, but the core protocol is universal.

**Step 1: Transport the Key**
First, we must get the file onto the device. Since we are simulating an air-gapped environment, we would typically use a USB cable. For simplicity in this lab, email the `~/cicd_stack/ca/pki/certs/ca.pem` file to an account accessible on the phone.
Open the email on your Android device and save the attachment to your **Downloads** folder.

**Step 2: The Security Settings**
Android buries certificate management deep within its security menus to prevent users from accidentally installing malicious roots.
1.  Open **Settings**.
2.  In the search bar at the top, type **"certificate"**.
3.  Select **"CA certificate"** (often found under *Encryption & Credentials* or *Install from storage*).
4.  If prompted with a frightening warning ("Your data won't be private"), click **"Install anyway"**. This warning exists because a malicious CA could inspect your traffic; however, in this case, *we* are the CA.
5.  Confirm your identity by entering your **Device PIN** or **Pattern**.

**Step 3: The Import and Verification**
The file explorer will open. Navigate to your **Downloads** folder (or wherever you saved the file).
Select the `ca.pem` file.
You should see a brief "toast" notification: **"CA certificate installed."**

To verify this, we must dig into the user credential store. On modern Android versions, the path is often convoluted:
Navigate to **Fingerprints, face data and screen lock** -> **Privacy** -> **More security settings** -> **Encryption and credentials** -> **User credentials**.

In this list, you should see your custom CA (e.g., `Local CICD Root CA`). With the root established, the phone now possesses the cryptographic chain of trust required to validate our server's identity.

## 6.3 The "CORS" Dragon

You might expect that installing the certificate would be the end of the battle. You return to the Mattermost app, enter the server URL (`https://192.168.x.x:8065`), and hit connect.

If we had not carefully configured our environment variables in Chapter 3, you would likely hit a second, invisible wall. The app might let you log in, but then immediately disconnect. Or, more subtly, text messages would work, but the status indicators would never update, and video calls would fail to initiate.

This is the **WebSocket** layer failing.

Mattermost uses a persistent WebSocket connection for real-time events (typing indicators, new messages, call signaling). When a mobile app initiates this connection, it sends an HTTP Origin header. Unlike a browser which sends the domain name, mobile apps (depending on the framework) often send `null` or the raw IP address as the Origin.

By default, the Mattermost server is strict. It checks the Origin header against its own `SiteURL`. If they don't match exactly, it slams the door on the WebSocket to prevent Cross-Site WebSocket Hijacking (CSWSH).

Because we are accessing the server via an IP address (`192.168.x.x`) but the server thinks its name is `mattermost.cicd.local`, this check fails. The text API (REST) works, but the real-time API (WebSocket) dies.

We solved this preemptively in **Section 3.4**. By setting `MM_SERVICESETTINGS_ALLOWCORSFROM=*`, we instructed the server to drop its shield and accept WebSocket connections from any origin. In a public internet deployment, this would be a security risk. In our private `cicd-net` fortress, it is a necessary concession to allow our mobile devices to speak freely with the Command Center.

With the Certificate installed and CORS unlocked, your mobile Command Center is now fully operational. You can log in, browse channels, and—most importantly—prepare to receive signals from the city we are about to wire up.