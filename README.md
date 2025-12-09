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

# Chapter 7: The Wiring (Part 1) - The Silent Observer

## 7.1 The "Click-Ops" Trap

Our Command Center is online, but it is currently a ghost town. It has no teams, no channels, and no users other than the admin.

In a typical "hobbyist" deployment, this is where you would start clicking. You would log into the web UI, click "Create Team," type "Engineering," click "Create Channel," type "builds," go to the System Console, create a Bot Account, copy the token, save it to a text file... and repeat this process for every tool you want to integrate.

This manual approach—often called "Click-Ops"—is an architectural trap.

1.  **It is not reproducible.** If your server crashes and you have to redeploy, you have to remember every single button click.
2.  **It is insecure.** Copy-pasting access tokens and webhook URLs through the browser clipboard is a great way to accidentally expose secrets or lose them.
3.  **It scales poorly.** Managing permissions for three tools is annoying; managing them for thirty is a full-time job.

We are building a **Software Supply Chain**, not a chatroom. Our infrastructure must be defined as code. The creation of our "Engineering" team, our standard channels (`#builds`, `#alerts`, `#code-reviews`), and the bot accounts that own them should be scripted, versioned, and executed automatically.

We need an "Electrician"—a script that walks into the empty building and wires up the lights before the residents arrive.

## 7.2 The Electrician (`04-configure-integrations.py`)

To achieve this automation, we rely on `mmctl`, the official command-line tool for Mattermost. Unlike the web API, `mmctl` has a superpower: **Local Mode**.

When running inside the container (or communicating via the Docker socket), `mmctl` can execute administrative commands without a username or password. It speaks directly to the server process over a Unix socket. This solves the "Bootstrap Paradox"—how do you authenticate to the API to create the first admin user if you don't have an admin user yet?

We will wrap `mmctl` in a Python script. While Bash is great for plumbing, Python is superior for parsing JSON responses and handling the logic flow of "If this webhook exists, don't create it; if it doesn't, create it and save the secret."

This script is our **Electrician**. It establishes the taxonomy of our city:

* **\#builds:** The noisy factory floor where Jenkins reports status.
* **\#code-reviews:** The library where GitLab announces changes.
* **\#alerts:** The dedicated red-phone line for SonarQube quality gate failures.

Create this file at `~/Documents/FromFirstPrinciples/articles/0011_cicd_part07_mattermost/04-configure-integrations.py`.

```python
#!/usr/bin/env python3

import subprocess
import json
import time
import sys
import os
import secrets
from pathlib import Path

# --- Configuration ---
CICD_ROOT = Path(os.environ.get("HOME")) / "cicd_stack"
ENV_FILE = CICD_ROOT / "cicd.env"
CONTAINER_NAME = "mattermost"
# We use --local to bypass authentication (requires EnableLocalMode=true)
MMCTL_CMD = ["docker", "exec", "-i", CONTAINER_NAME, "mmctl", "--local", "--json"]
ADMIN_USER = "warren.jitsing" # The user who will own the webhooks

# --- Entities to Create ---
TEAM_NAME = "engineering"
CHANNELS = ["builds", "code-reviews", "alerts", "town-square"]

def run_mmctl(args, allow_fail=False):
    """Runs an mmctl command inside the container and returns parsed JSON."""
    cmd = MMCTL_CMD + args
    try:
        # check=True is removed so we can handle the return code manually
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if result.returncode != 0:
            if allow_fail:
                return None
            print(f"Error running mmctl: {result.stderr}")
            sys.exit(1)

        output = result.stdout.strip()
        if not output:
            return None

        # Attempt 1: Parse the full output as JSON
        try:
            data = json.loads(output)
            if isinstance(data, list):
                return data[0] if data else None
            return data
        except json.JSONDecodeError:
            # Attempt 2: Fallback for mixed output
            lines = output.split('\n')
            if lines:
                return json.loads(lines[-1])
            return None

    except Exception as e:
        if allow_fail:
            return None
        print(f"Unexpected error parsing mmctl output: {e}")
        sys.exit(1)

def read_env_file():
    """Reads the current state of cicd.env."""
    if not ENV_FILE.exists():
        return ""
    with open(ENV_FILE, "r") as f:
        return f.read()

def append_to_env(key, value):
    """Appends a secret to the master cicd.env file."""
    print(f"   💾 Writing {key} to cicd.env...")
    with open(ENV_FILE, "a") as f:
        f.write(f"\n{key}=\"{value}\"\n")

def wait_for_server():
    print("⏳ Waiting for Mattermost to be ready...")
    for _ in range(30):
        try:
            subprocess.run(
                ["docker", "exec", CONTAINER_NAME, "mmctl", "--local", "system", "version"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            print("✅ Mattermost is responding.")
            return
        except subprocess.CalledProcessError:
            time.sleep(2)
    print("❌ Timeout waiting for Mattermost.")
    sys.exit(1)

def main():
    if not ENV_FILE.exists():
        print(f"❌ Error: {ENV_FILE} not found.")
        sys.exit(1)

    wait_for_server()
    env_content = read_env_file()

    # 1. Create Team
    print(f"--- Configuring Team: {TEAM_NAME} ---")
    res = run_mmctl(["team", "create", "--name", TEAM_NAME, "--display-name", "Engineering"], allow_fail=True)
    if res:
        print(f"   ✅ Team '{TEAM_NAME}' created.")
    else:
        print(f"   ℹ️  Team '{TEAM_NAME}' likely exists.")

    # FIX: Add Admin User to Team so they can own webhooks
    print(f"   Ensuring {ADMIN_USER} is in {TEAM_NAME}...")
    run_mmctl(["team", "users", "add", TEAM_NAME, ADMIN_USER], allow_fail=True)

    # 2. Create Channels
    print(f"--- Configuring Channels ---")
    for channel in CHANNELS:
        subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "mmctl", "--local", "channel", "create",
             "--team", TEAM_NAME, "--name", channel, "--display-name", channel.capitalize()],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print(f"   ✅ Channel '#{channel}' ensured.")

    # 3. Configure Jenkins Integration (Bot + Webhook)
    print(f"--- Configuring Jenkins Integration ---")

    # 3a. Ensure Bot User Exists (Identity)
    bot_password = ""
    if "JENKINS_BOT_PASSWORD" in env_content:
        for line in env_content.splitlines():
            if line.startswith("JENKINS_BOT_PASSWORD="):
                bot_password = line.split("=", 1)[1].strip('"')
    else:
        print("   🎲 Generating high-entropy Bot Password...")
        bot_password = secrets.token_urlsafe(24)
        append_to_env("JENKINS_BOT_PASSWORD", bot_password)
        env_content += f"\nJENKINS_BOT_PASSWORD={bot_password}"

    bot_email = "jenkins-bot@cicd.local"
    bot_user = "jenkins-bot"

    print("   Ensuring Jenkins Bot User exists...")
    run_mmctl(["user", "create", "--email", bot_email, "--username", bot_user, "--password", bot_password], allow_fail=True)
    run_mmctl(["user", "verify", bot_user], allow_fail=True)
    run_mmctl(["team", "users", "add", TEAM_NAME, bot_user], allow_fail=True)

    # 3b. Create Webhook for Notifications (Required by Jenkins Notification Plugin)
    if "JENKINS_MATTERMOST_WEBHOOK" in env_content:
        print("   ℹ️  JENKINS_MATTERMOST_WEBHOOK already exists. Skipping.")
    else:
        print("   Creating Incoming Webhook for #builds...")
        # FIX: Use fully qualified channel name and ADMIN_USER ownership
        hook_res = run_mmctl(["webhook", "create-incoming", "--user", ADMIN_USER, "--channel", f"{TEAM_NAME}:builds", "--display-name", "Jenkins", "--description", "Build Notifications"])

        if hook_id := hook_res.get("id"):
            webhook_url = f"https://mattermost.cicd.local:8065/hooks/{hook_id}"
            append_to_env("JENKINS_MATTERMOST_WEBHOOK", webhook_url)
            env_content += f"\nJENKINS_MATTERMOST_WEBHOOK={webhook_url}"

    # 4. Create SonarQube Webhook (#alerts)
    print(f"--- Configuring SonarQube Webhook ---")

    if "SONAR_MATTERMOST_WEBHOOK" in env_content:
        print("   ℹ️  SONAR_MATTERMOST_WEBHOOK already exists. Skipping.")
    else:
        print("   Creating Incoming Webhook for #alerts...")
        hook_res = run_mmctl(["webhook", "create-incoming", "--user", ADMIN_USER, "--channel", f"{TEAM_NAME}:alerts", "--display-name", "SonarQube", "--description", "Quality Gate Alerts"])

        if hook_id := hook_res.get("id"):
            webhook_url = f"https://mattermost.cicd.local:8065/hooks/{hook_id}"
            append_to_env("SONAR_MATTERMOST_WEBHOOK", webhook_url)
            env_content += f"\nSONAR_MATTERMOST_WEBHOOK={webhook_url}"

    # 5. Create GitLab Webhook (#code-reviews)
    print(f"--- Configuring GitLab Webhook ---")

    if "MATTERMOST_CODE_REVIEW_WEBHOOK" in env_content:
        print("   ℹ️  MATTERMOST_CODE_REVIEW_WEBHOOK already exists. Skipping.")
    else:
        print("   Creating Incoming Webhook for #code-reviews...")
        hook_res = run_mmctl(["webhook", "create-incoming", "--user", ADMIN_USER, "--channel", f"{TEAM_NAME}:code-reviews", "--display-name", "GitLab", "--description", "Commit and Merge Request Events"])

        if hook_id := hook_res.get("id"):
            webhook_url = f"https://mattermost.cicd.local:8065/hooks/{hook_id}"
            append_to_env("MATTERMOST_CODE_REVIEW_WEBHOOK", webhook_url)

    print("\n✅ Configuration Complete.")
    print("   Restart Jenkins/SonarQube to pick up new secrets.")

if __name__ == "__main__":
    main()
```

### Deconstructing the Electrician

**1. The "Local Mode" Bypass**
The script uses `docker exec ... mmctl --local`. This is the key. It allows us to configure the server from the outside without needing to manually create an admin user first or wrestle with login tokens. We are manipulating the server's brain directly via its command socket.

**2. Idempotency (The "Check First" Logic)**
Notice how the script checks for existing environment variables (`if "JENKINS_MATTERMOST_WEBHOOK" in env_content`). This prevents duplicate webhooks. If you run the script ten times, it will only create the resources once. This is a core tenet of Infrastructure as Code.

**3. The Secret Extraction**
When `mmctl` creates a webhook, it returns a JSON object containing the ID. We parse this ID immediately, construct the full URL (`https://mattermost.../hooks/ID`), and append it to our master `cicd.env` file. This eliminates the "Copy-Paste Risk." The secret moves directly from the generator to the vault, untouched by human hands.

## 7.3 The Connector (`05-connect-jenkins.sh`)

We have created the destination (the `#builds` channel) and generated the address (the webhook URL). Now we must hand that address to the Factory.

In **Article 8**, we deployed Jenkins using **Configuration as Code (JCasC)**. We did not use the UI to set up our system message or credentials. We defined them in a YAML file (`jenkins.yaml`). To add Mattermost notifications, we must modify that YAML file.

However, we cannot simply hardcode the webhook URL into the YAML. That would be a security violation (checking secrets into git) and an idempotency failure (the secret is generated dynamically by the previous script).

We need a "Hot-Patcher." We need a script that reads the fresh secret from `cicd.env`, injects it into the `jenkins.env` file, and then updates the `jenkins.yaml` configuration to use that variable.

We will split this into two parts: a Python helper to handle the YAML surgery, and a Bash script to orchestrate the deployment.

**Part 1: The YAML Surgeon**

Create this file at `~/Documents/FromFirstPrinciples/articles/0011_cicd_part07_mattermost/update_jcasc_mattermost.py`.

```python
#!/usr/bin/env python3

import sys
import yaml
import os

# Target the LIVE configuration
JCAS_FILE = os.path.expanduser("~/cicd_stack/jenkins/config/jenkins.yaml")

def update_jcasc():
    print(f"[INFO] Reading JCasC file: {JCAS_FILE}")

    try:
        with open(JCAS_FILE, 'r') as f:
            jcasc = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {JCAS_FILE}")
        sys.exit(1)

    # Configure Mattermost Notification Plugin (Global)
    print("[INFO] Injecting Mattermost Global Configuration...")

    if 'unclassified' not in jcasc:
        jcasc['unclassified'] = {}

    # CORRECTED SCHEMA:
    # 1. Valid attributes only (endpoint, room, buildServerUrl, icon).
    # 2. Room set to 'engineering@builds' (Team@Channel format verified by user).
    jcasc['unclassified']['mattermostNotifier'] = {
        'endpoint': '${MATTERMOST_JENKINS_WEBHOOK_URL}',
        'room': 'engineering@builds',
        'buildServerUrl': 'https://jenkins.cicd.local:10400/',
        'icon': 'https://mattermost.org/wp-content/uploads/2016/04/icon.png'
    }

    # Write back to file
    print("[INFO] Writing updated JCasC file...")
    with open(JCAS_FILE, 'w') as f:
        yaml.dump(jcasc, f, default_flow_style=False, sort_keys=False)

    print("[INFO] JCasC update complete.")

if __name__ == "__main__":
    update_jcasc()
```

**Part 2: The Orchestrator**

This script ties it all together. It reads the secret, runs the python helper, and then triggers a Jenkins redeployment to pick up the changes.

Create this file at `~/Documents/FromFirstPrinciples/articles/0011_cicd_part07_mattermost/05-connect-jenkins.sh`.

```bash
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
```

### Deconstructing the Connector

**1. The Variable Hand-Off**
This script performs a crucial bridging operation. It takes `JENKINS_MATTERMOST_WEBHOOK` (which lives in the host's `cicd.env`) and injects it into `jenkins.env` as `MATTERMOST_JENKINS_WEBHOOK_URL`. Why rename it? Because inside the Jenkins container, we want clear namespacing. This variable is then referenced in the JCasC file as `${MATTERMOST_JENKINS_WEBHOOK_URL}`. This ensures the secret is never written to disk in the YAML file; it is only resolved in memory at runtime.

**2. The Team@Channel Format**
In the Python script, notice the room configuration: `'room': 'engineering@builds'`. The Mattermost plugin requires this specific syntax to target a channel within a specific team. If we just put `builds`, it might default to the wrong team or fail silently.

**3. The Redeployment Trigger**
The script concludes by running `03-deploy-controller.sh` from the Jenkins directory. This is not optional. JCasC reloading can sometimes be done on the fly, but injecting new environment variables (the webhook URL) requires a container restart. We force a clean deploy to ensure the new "nerve" is fully attached.

# Chapter 7: The Wiring (Part 1) - The Silent Observer

## 7.4 The Pipeline Update (`Jenkinsfile`)

We have connected the cable (the webhook), but we haven't told the operator when to press the button.

While the JCasC configuration we just applied sets up the *default* connection details (the endpoint and the default room), we want granular control over *what* gets sent and *where*.

Specifically, we want to implement a routing logic that matches our "City" taxonomy:

1.  **General Status:** Success/Failure notifications for the build itself should go to **\#builds**.
2.  **Quality Alerts:** If the Inspector (SonarQube) blocks the pipeline, that specific alarm should ring in **\#alerts**.

To achieve this, we must update our project's `Jenkinsfile`. We will use the `mattermostSend` step provided by the plugin. Note how we override the channel in the Quality Gate block to route that specific message to `engineering@alerts`.

Update your `Jenkinsfile` in the `0004_std_lib_http_client` project (or your test repo) with the following content:

```groovy
pipeline {
    agent {
        label 'general-purpose-agent'
    }

    stages {
        stage('Setup & Build') {
            steps {
                echo '--- Building Project ---'
                sh 'chmod +x ./setup.sh'
                sh './setup.sh'
            }
        }

        stage('Test & Coverage') {
            steps {
                echo '--- Running Tests ---'
                sh 'chmod +x ./run-coverage-cicd.sh'
                sh './run-coverage-cicd.sh'
            }
        }

        stage('Code Analysis') {
            steps {
                script {
                    def sonarProjectKey = sh(returnStdout: true, script: 'grep "^sonar.projectKey=" sonar-project.properties | cut -d= -f2').trim()

                    def sonarHostUrl = "http://sonarqube.cicd.local:9000"

                    withSonarQubeEnv('SonarQube') {
                        sh 'sonar-scanner'
                    }

                    // 3. Wait for Quality Gate
                    timeout(time: 5, unit: 'MINUTES') {
                        def qg = waitForQualityGate()
                        if (qg.status != 'OK') {
                            // ROUTING: Quality Gate failures go to #alerts
                            mattermostSend (
                                color: 'danger',
                                channel: 'engineering@alerts',
                                message: ":no_entry: **Quality Gate Failed**: ${qg.status}\n<${sonarHostUrl}/dashboard?id=${sonarProjectKey}|View Analysis>"
                            )
                            error "Pipeline aborted due to quality gate failure: ${qg.status}"
                        }
                    }
                }
            }
        }

        stage('Package') {
            steps {
                echo '--- Packaging Artifacts ---'
                sh 'mkdir -p dist'

                dir('build_release') {
                    sh 'cpack -G TGZ -C Release'
                    sh 'mv *.tar.gz ../dist/'
                }

                dir('src/rust') {
                    sh 'cargo package'
                    sh 'cp target/package/*.crate ../../dist/'
                }

                sh 'cp build_release/wheelhouse/*.whl dist/'
            }
        }

        stage('Publish') {
            steps {
                echo '--- Publishing to Artifactory ---'

                rtUpload (
                    serverId: 'artifactory',
                    spec: """{
                          "files": [
                            {
                              "pattern": "dist/*",
                              "target": "generic-local/http-client/${BUILD_NUMBER}/",
                              "flat": "true"
                            }
                          ]
                    }""",
                    failNoOp: true,
                    buildName: "${JOB_NAME}",
                    buildNumber: "${BUILD_NUMBER}"
                )

                rtPublishBuildInfo (
                    serverId: 'artifactory',
                    buildName: "${JOB_NAME}",
                    buildNumber: "${BUILD_NUMBER}"
                )
            }
        }
    }

    // Global Post Actions: Standard notifications go to default channel (#builds)
    post {
        failure {
            mattermostSend (
                color: 'danger',
                message: ":x: **Build Failed**\n**Job:** ${env.JOB_NAME} #${env.BUILD_NUMBER}\n(<${env.BUILD_URL}|Open Build>)"
            )
        }
        success {
            mattermostSend (
                color: 'good',
                message: ":white_check_mark: **Build Succeeded**\n**Job:** ${env.JOB_NAME} #${env.BUILD_NUMBER}\n(<${env.BUILD_URL}|Open Build>)"
            )
        }
    }
}
```

### Deconstructing the Pipeline

**1. The "Global Post" Block (The Heartbeat)**
At the bottom of the file, the `post` block handles the routine heartbeat of the factory. Whether the build succeeds or fails, `mattermostSend` fires. Because we do not specify a `channel` parameter here, it defaults to the configuration we injected via JCasC (`engineering@builds`). This creates a steady stream of "Green/Red" status updates in our main channel.

**2. The Conditional Alert (The Alarm Bell)**
Inside the `Code Analysis` stage, we have a specific `if (qg.status != 'OK')` block. Here, we invoke `mattermostSend` with `channel: 'engineering@alerts'`. This is a critical pattern. We do not want to flood the general `#builds` channel with nitty-gritty quality gate details. By routing this specific failure event to `#alerts`, we ensure that the "Red Phone" only rings when something actually requires inspection.

**3. Contextual Linking**
Notice how we construct the message string: `<${sonarHostUrl}/dashboard...|View Analysis>`. Mattermost supports Markdown-style links. We are not just saying "It failed"; we are providing a one-click path for the engineer to jump directly to the SonarQube dashboard to see *why* it failed. This reduces the "Time to Diagnosis."

## 7.5 Verification: First Contact

We have completed the electrical wiring. The "Electrician" (`04-configure-integrations.py`) built the channel and the bot. The "Connector" (`05-connect-jenkins.sh`) handed the webhook to Jenkins. The "Pipeline" (`Jenkinsfile`) knows exactly where to route the signals.

Now, we close the circuit.

1.  **Commit and Push:** Commit the updated `Jenkinsfile` to your GitLab repository using our standard conventional commit style.
    ```bash
    git add Jenkinsfile
    git commit -m ":package: build(Jenkinsfile): add mattermost notifications"
    git push
    ```
2.  **Open your Mattermost Tab:** Navigate to the **Engineering** team and open the **\#builds** channel. It should be empty, waiting for a signal.
3.  **Trigger the Signal:** If your GitLab webhook (from Article 8) is active, the push will trigger a build automatically. If not, open your Jenkins dashboard (`https://jenkins.cicd.local:10400`) and click **"Build Now"** on the project.
4.  **Observe:**

Wait for the pipeline to finish. Our configuration is designed to be low-noise: it does not spam the channel when the build *starts*, only when it *concludes*.

Once the build finishes, you will see the **Jenkins** bot appear in the `#builds` channel with a definitive verdict: either a green **"Build Succeeded"** or a red **"Build Failed"** message, complete with a hyperlink to the build logs.

If you see this, the nervous system is live. The "Silent City" is no longer silent. Every time a build verdict is reached, the event is broadcast to the team.

However, try to reply to the bot. Type: `@jenkins help` in the channel.

Nothing happens.

This is a **Unidirectional (One-Way)** connection. Jenkins can talk to us, but we cannot talk to Jenkins. In a true "Command Center," we demand control. We want to trigger builds, check logs, and restart servers directly from the chat window without context-switching to the Jenkins UI.

To achieve this, we need to upgrade from simple Webhooks to a full **Interactive Plugin**. This brings us to Chapter 8.

# Chapter 8: The Wiring (Part 2) - The Interactive Agent

## 8.1 Beyond Notification: The Need for Command

In the previous chapter, we successfully wired the nerves of our city. When Jenkins finishes a job, our Mattermost channel lights up. This is valuable—it reduces the "polling loop" where engineers obsessively refresh a browser tab.

But it is passive. It is **Read-Only**.

A true "Command Center" must be **Read-Write**. We don't just want to know that a build failed; we want to restart it. We don't just want to see a deployment notification; we want to *trigger* the deployment. We want to treat the chat window as a shared CLI (Command Line Interface) for our infrastructure.

This is the domain of **Slash Commands**.

We want to type `/jenkins build articles/0004_std_lib_http_client` and have the Factory immediately spin up the turbines. We want to type `/jenkins get-log` to debug a failure without leaving the chat. We even want the power to reboot the factory floor remotely with `/jenkins safe-restart`.

To achieve this, the standard "Incoming Webhook" we used in Chapter 7 is insufficient. That was just a simple POST endpoint. For interactive control, we need the dedicated **Mattermost Jenkins Plugin**. This plugin acts as a bridge, translating Mattermost slash commands into Jenkins API calls, and translating Jenkins API responses back into interactive chat messages.

However, enabling this plugin in a "Code-First" environment involves overcoming a specific configuration hurdle that trips up many automated deployments: the **Plugin ID Dragon**.

## 8.2 The "Missing Limb" Dragon

In **Chapter 3**, when we generated our `mattermost.env` file, we included a specific line to enable the Jenkins plugin:

`MM_PLUGINSETTINGS_PLUGINSTATES={"jenkins":{"Enable":true} ... }`

This directive tells Mattermost to *load* the plugin. However, unlike the "Boards" or "Playbooks" features which are baked into the Enterprise image, the Jenkins plugin is an external add-on. It does not exist on the disk. We tried to flip a switch for a lightbulb that isn't screwed in.

To make this work, we have two distinct tasks:
1.  **Installation:** We must download the plugin bundle (`.tar.gz`) from the release repository and physically upload it to the Mattermost server.
2.  **Configuration:** Once installed, the plugin is a blank slate. It doesn't know where Jenkins is, and it doesn't have the encryption keys required to talk to it.

Here lies the architectural dragon: **Plugin Configuration vs. Environment Variables.**

For core Mattermost settings (like database URL), we can simply set `MM_SQLSETTINGS_DATASOURCE`. But for *Plugins*, there is no such mechanism. You cannot set `MM_PLUGINSETTINGS_JENKINS_BASEURL`. Plugin settings live in a complex, unstructured JSON blob inside the server's state.

If we were using "Click-Ops," we would manually upload the file in the System Console and then type the secrets into the UI. But we are building a reproducible city. We need a "Surgeon"—a script that can perform this transplant operation programmatically.

This surgeon must:
1.  **Download** the latest plugin release.
2.  **Install** it via `mmctl` (the CLI tool).
3.  **Inject** the configuration payload that binds the plugin to `http://jenkins.cicd.local:10400` using the keys we generated in Chapter 3.

## 8.3 The Surgeon (`09-install-jenkins-plugin.py`)

We will now write the script that performs this delicate operation. This is not a simple "fire and forget" command; it is a multi-step workflow.

The script acts as a specialized package manager. It:

1.  **Unlocks** the server's write-protection (`EnableUploads`).
2.  **Downloads** the plugin bundle (`.tar.gz`) from the release repository.
3.  **Installs** and **Enables** the binary using `mmctl`.
4.  **Injects** the specific configuration keys (URL and Encryption Key) using granular `config set` commands.
5.  **Re-locks** the server.

Create this file at `~/Documents/FromFirstPrinciples/articles/0011_cicd_part07_mattermost/09-install-jenkins-plugin.py`.

```python
#!/usr/bin/env python3

import subprocess
import os
import sys
import urllib.request
from pathlib import Path

# --- Configuration ---
# Paths
CICD_ROOT = Path(os.environ.get("HOME")) / "cicd_stack"
ENV_FILE = CICD_ROOT / "cicd.env"

# Docker / Plugin Info
CONTAINER_NAME = "mattermost"
PLUGIN_URL = "https://github.com/mattermost-community/mattermost-plugin-jenkins/releases/download/v1.1.0/jenkins-1.1.0.tar.gz"
PLUGIN_FILE = "jenkins-1.1.0.tar.gz"
PLUGIN_ID = "jenkins" # Community version ID

# Commands
MMCTL = ["docker", "exec", "-i", CONTAINER_NAME, "mmctl", "--local"]

def load_secret_key():
    """Reads the Jenkins Encryption Key from cicd.env."""
    if not ENV_FILE.exists():
        print(f"❌ Error: {ENV_FILE} not found.")
        sys.exit(1)

    with open(ENV_FILE, "r") as f:
        for line in f:
            if line.startswith("MATTERMOST_JENKINS_PLUGIN_KEY="):
                return line.split('=', 1)[1].strip().strip('"\'')
    return None

def run_command(cmd, description):
    """Runs a shell command and prints status."""
    print(f"   ⚙️  {description}...", end=" ", flush=True)
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print("✅")
    except subprocess.CalledProcessError as e:
        print("❌")
        print(f"      Error: {e.stderr.decode().strip()}")
        sys.exit(1)

def set_config(path, value):
    """Sets a config value via mmctl."""
    # Note: mmctl requires string values
    cmd = MMCTL + ["config", "set", path, str(value)]
    run_command(cmd, f"Setting {path}")

def main():
    print("--- 🤖 Automating Jenkins Plugin (mmctl edition) ---")

    # 0. Pre-flight Check
    jenkins_key = load_secret_key()
    if not jenkins_key:
        print("❌ Error: MATTERMOST_JENKINS_PLUGIN_KEY not found in cicd.env")
        sys.exit(1)

    # 1. Unlock Uploads
    set_config("PluginSettings.EnableUploads", "true")

    # 2. Download
    print(f"   ⬇️  Downloading Plugin...", end=" ", flush=True)
    if not os.path.exists(PLUGIN_FILE):
        try:
            urllib.request.urlretrieve(PLUGIN_URL, PLUGIN_FILE)
            print("✅")
        except Exception as e:
            print("❌")
            print(f"      Download failed: {e}")
            sys.exit(1)
    else:
        print("✅ (Cached)")

    # 3. Transfer
    print(f"   📦 Copying to container...", end=" ", flush=True)
    subprocess.run(["docker", "cp", PLUGIN_FILE, f"{CONTAINER_NAME}:/tmp/{PLUGIN_FILE}"], check=True)
    print("✅")

    # 4. Install (Robust)
    print(f"   ⚙️  Installing Plugin bundle...", end=" ", flush=True)
    try:
        subprocess.run(MMCTL + ["plugin", "add", f"/tmp/{PLUGIN_FILE}"], check=True, capture_output=True)
        print("✅")
    except subprocess.CalledProcessError as e:
        if "already installed" in e.stderr.decode():
            print("⚠️  (Already Installed)")
        else:
            print("❌")
            print(f"      Error: {e.stderr.decode().strip()}")
            sys.exit(1)

    # 5. Enable
    # This initializes the default config structure in the DB
    run_command(MMCTL + ["plugin", "enable", PLUGIN_ID], f"Enabling '{PLUGIN_ID}'")

    # 6. Configure via mmctl
    # We use the exact keys confirmed from your config dump: 'jenkinsurl' and 'encryptionkey'
    # The Base Path for mmctl is PluginSettings.Plugins.jenkins
    print("   🔌 Configuring Plugin settings...")

    # 6a. Set URL
    set_config(f"PluginSettings.Plugins.{PLUGIN_ID}.jenkinsurl", "https://jenkins.cicd.local:10400")

    # 6b. Set Encryption Key
    set_config(f"PluginSettings.Plugins.{PLUGIN_ID}.encryptionkey", jenkins_key)

    # 7. Re-Lock Uploads
    set_config("PluginSettings.EnableUploads", "false")

    # 8. Cleanup
    if os.path.exists(PLUGIN_FILE):
        os.remove(PLUGIN_FILE)

    print("[SUCCESS] Jenkins Plugin Installed & Configured.")

if __name__ == "__main__":
    main()
```

### Deconstructing the Surgeon

**1. The `EnableUploads` Toggle (Security)**
By default, Mattermost prevents plugin uploads to protect the server from unauthorized code execution.
`set_config("PluginSettings.EnableUploads", "true")`
The script temporarily lifts this gate, installs the software, and then immediately slams the gate shut again. This reduces the window of vulnerability to mere seconds.

**2. The Granular Config (`PluginSettings.Plugins...`)**
Unlike environment variables which are broad, `mmctl config set` allows us to target deeply nested JSON keys using dot notation.
`PluginSettings.Plugins.jenkins.encryptionkey`
This writes directly to the plugin's private storage area in the `config.json`. It is cleaner and safer than downloading and patching the entire server configuration blob.

**3. The Encryption Key Injection**
We pull the 32-byte AES key (`MATTERMOST_JENKINS_PLUGIN_KEY`) from our environment and inject it. This ensures that when the plugin encrypts your personal Jenkins API token in the next step, it uses a key that persists across server restarts. Without this, your handshake would break every time the container redeployed.

## 8.4 The Handshake: Establishing Command

The Surgeon has successfully transplanted the plugin. Now, we must wake the patient.

We have established the server-to-server link, but we have not yet established the **User-to-User** link. When you type a command, Jenkins needs to know *who* you are. It cannot simply trust your Mattermost username; it needs a valid Jenkins API token belonging to your user.

This requires a manual credential exchange.

### Protocol 1: The Connection (Manual)

1.  **Generate the Token (Jenkins Side):**

    * Navigate to your Jenkins Dashboard (`https://jenkins.cicd.local:10400`).
    * Click on your **Username** (top right corner) -\> **Configure**.
    * Scroll to the **API Token** section and click **Add new Token**.
    * Name it `Mattermost-Bot` and click **Generate**.
    * **Copy the token immediately.** (You will never see it again).

2.  **Perform the Handshake (Mattermost Side):**

    * Go to the **\#builds** channel in Mattermost.
    * Type the connect command with your username and the token:
      ```bash
      /jenkins connect <your_username> <your_api_token>
      ```
      *(Example: `/jenkins connect warren.jitsing 11d38...9a`)*

3.  **Confirmation:**

    * The bot will reply privately: *"Validating Jenkins credentials..."*
    * Followed by: *"Your Jenkins account has been successfully connected to Mattermost."*

### Protocol 2: The Command

Now, let's test the control.

The error `Don't have key "Location"` is a common trap. It occurs if you try to build a job name that doesn't exist. Jenkins returns a generic page instead of a Queue ID, confusing the plugin.

You must use the exact path. Since we are using Multibranch Pipelines inside a Folder (from Article 8), the path includes the folder, the repo, and the branch.

1.  **Trigger:**
    Type the following command:

    ```bash
    /jenkins build articles/0004_std_lib_http_client/main
    ```

2.  **Response:**
    You will see immediate feedback confirming the command was received and processed:

    > **Jenkins BOT**
    > Initiated by Jenkins user: admin
    > Job 'articles/0004\_std\_lib\_http\_client/main' has been triggered and is in queue.

    Moments later, as the executor picks up the job:

    > **Jenkins BOT**
    > Initiated by Jenkins user: admin
    > Job 'articles/0004\_std\_lib\_http\_client/main' - \#14 has been started
    > Build URL : [https://jenkins.cicd.local:10400/](https://www.google.com/search?q=https://jenkins.cicd.local:10400/)...

    Notice the difference? When the *pipeline* runs automatically (via git push), it is silent until the end. But when *you* trigger it manually via chat, the bot confirms receipt immediately.

### Protocol 3: The Investigation

If you need to peek at the logs while the job is running (or after a failure) without leaving the chat:

1.  **Get Log:**
    ```bash
    /jenkins get-log articles/0004_std_lib_http_client/main
    ```
2.  **Response:**
    The bot will fetch the last few lines of the console output and post them as a code snippet directly in the channel.

We have achieved the **Interactive Loop**. We can Observe (Notifications), Orient (Get Log), Decide (Analyze), and Act (Rebuild)—all without touching a browser tab.

# Chapter 9: The Wiring (Part 3) - The Library & The Inspector

## 9.1 The Library: Notifications (`06-connect-gitlab.py`)

We have connected the Factory (Jenkins) to our "Town Square." Now we turn our attention to the Library (GitLab).

Our first goal is to ensure that activity in the library—commits, merge requests, and pipeline statuses—is broadcast to the `#code-reviews` channel we established in Chapter 7.

While GitLab has a native "Slack notifications" integration, it also supports Mattermost natively. We will use a Python script to programmatically configure this integration for our specific project (`0004_std_lib_http_client`). This script acts as **The Diplomat**: it takes the webhook URL generated by the Mattermost "Electrician" (`04`) and registers it with the GitLab project.

Create this file at `~/Documents/FromFirstPrinciples/articles/0011_cicd_part07_mattermost/06-connect-gitlab.py`.

```python
#!/usr/bin/env python3

import os
import ssl
import json
import urllib.request
import urllib.error
import sys
from pathlib import Path

# --- Configuration ---
ENV_FILE = Path(os.environ.get("HOME")) / "cicd_stack" / "cicd.env"
GITLAB_URL = "https://gitlab.cicd.local:10300"
TARGET_GROUP = "Articles"
TARGET_PROJECT = "0004_std_lib_http_client"

def load_env():
    if not ENV_FILE.exists():
        print(f"❌ Error: {ENV_FILE} not found.")
        sys.exit(1)

    with open(ENV_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip().strip('"\'')

def get_ssl_context():
    # Uses the host's system trust store (where our CA is installed)
    return ssl.create_default_context()

def make_request(url, method="GET", data=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["PRIVATE-TOKEN"] = token

    if data:
        data = json.dumps(data).encode("utf-8")

    req = urllib.request.Request(url, headers=headers, data=data, method=method)

    try:
        with urllib.request.urlopen(req, context=get_ssl_context()) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        print(f"   ⛔ HTTP Error {e.code}: {e.reason}")
        try:
            print(f"      {e.read().decode()}")
        except:
            pass
        sys.exit(1)

def main():
    load_env()
    token = os.getenv("GITLAB_API_TOKEN")
    webhook_url = os.getenv("MATTERMOST_CODE_REVIEW_WEBHOOK")

    print(f"--- Connecting GitLab to Mattermost ---")

    if not token:
        print("❌ Error: GITLAB_API_TOKEN not found in cicd.env.")
        sys.exit(1)
    if not webhook_url:
        print("❌ Error: MATTERMOST_CODE_REVIEW_WEBHOOK not found in cicd.env.")
        print("   Please run 04-configure-integrations.py first.")
        sys.exit(1)

    # 1. Find Project ID
    print(f"   🔎 Finding project '{TARGET_GROUP}/{TARGET_PROJECT}'...")
    projects = make_request(f"{GITLAB_URL}/api/v4/projects?search={TARGET_PROJECT}", token=token)

    project_id = None
    target_path = f"{TARGET_GROUP}/{TARGET_PROJECT}".lower()

    for p in projects:
        if p["path_with_namespace"].lower() == target_path:
            project_id = p["id"]
            break

    if not project_id:
        print(f"   ❌ Project not found.")
        sys.exit(1)

    print(f"   ✅ Found Project ID: {project_id}")

    # 2. Configure Integration (Idempotent PUT)
    # We use PUT to enforce the state defined in our environment.
    print(f"   ⚙️  Enforcing Integration Configuration...")

    config_data = {
        "webhook": webhook_url,
        "username": "GitLab",
        "notify_only_broken_pipelines": False,
        "push_events": True,
        "merge_requests_events": True,
        "pipeline_events": True,
        "tag_push_events": True,
        "branches_to_be_notified": "all"
    }

    make_request(
        f"{GITLAB_URL}/api/v4/projects/{project_id}/integrations/mattermost",
        method="PUT",
        data=config_data,
        token=token
    )

    print(f"   ✅ Integration synced. Notifications active in #code-reviews.")
    print("[SUCCESS] GitLab integration complete.")

if __name__ == "__main__":
    main()
```

### Deconstructing the Diplomat

**1. The Target Discovery**
The script does not assume the project ID. It searches for `Articles/0004_std_lib_http_client`. This makes the script portable; if you recreate the repo, the ID changes, but the script still finds the correct target.

**2. The Integration Payload**
We use the `integrations/mattermost` endpoint. Notice the configuration:

* `push_events`: True. Every commit triggers a notification.
* `merge_requests_events`: True. Opening or merging an MR alerts the channel.
* `pipeline_events`: True. GitLab CI status changes are reported (distinct from Jenkins).
* `webhook`: This comes directly from `MATTERMOST_CODE_REVIEW_WEBHOOK`, ensuring the messages land in `#code-reviews`.

**3. Idempotency (PUT)**
We use the HTTP `PUT` method. If the integration doesn't exist, GitLab creates it. If it does exist, GitLab updates it to match our JSON payload exactly. This prevents "configuration drift."

-----

## 9.2 The Library: Identity (Manual OAuth Setup)

Webhooks give us **Notifications**. But to achieve **Interaction** (viewing your personal To-Do list, subscribing to specific repos, and seeing MR previews in the sidebar), we need **OAuth2**.

The Mattermost GitLab Plugin needs permission to act on your behalf. This requires creating a "User-Scoped Application" in GitLab. Because this process generates sensitive secrets that are displayed only once, we perform this step manually in the GitLab UI.

**Step 1: Navigate to Applications**

1.  Log in to GitLab (`https://gitlab.cicd.local:10300`).
2.  Click your **Avatar** (top right) -\> **Preferences**.
3.  In the left sidebar, select **Applications**.
4.  Click **Add new application**.

**Step 2: Define the Treaty**
Fill in the form with the following details. Be precise with the Redirect URIs.

* **Name:** `Mattermost Chat Ops`

* **Redirect URI:**
  You must provide *two* URIs: one for the internal DNS name (for desktop/browser users) and one for the IP address (for mobile users/Entry Mode).

  ```text
  https://mattermost.cicd.local:8065/plugins/com.github.manland.mattermost-plugin-gitlab/oauth/complete
  https://<YOUR_LAN_IP>:8065/plugins/com.github.manland.mattermost-plugin-gitlab/oauth/complete
  ```

  *(Replace `<YOUR_LAN_IP>` with your host machine's IP, e.g., `192.168.0.105`)*

* **Confidential:** `Yes` (Checked)

* **Scopes:** Select the following:

    * `api` (Access the API on your behalf)
    * `read_user` (Read your personal information)

**Step 3: Secure the Secrets**
Click **Save application**.
GitLab will present you with an **Application ID** and a **Secret**.

> **⚠️ CRITICAL:** Keep this page open or copy these values immediately. You cannot see the Secret again.

We will use these two values in the next section to configure the Mattermost server.

## 9.3 The Messenger (`07-connect-sonarqube.py`)

We have connected the Factory and the Library. Now we turn to **The Inspector**.

SonarQube analyzes our code quality. In **Article 10**, we established a "Quality Gate"—a pass/fail threshold for our software. If the Inspector fails a build because of low test coverage or security vulnerabilities, we want that alarm to ring immediately in the dedicated **\#alerts** channel.

We have already created the destination (the Webhook URL for `#alerts`) in script `04`. Now we must tell SonarQube to use it.

**Architectural Note: The Formatting Mismatch**
It is important to note a limitation here. SonarQube sends webhooks with a complex, nested JSON payload detailing the quality gate status. Mattermost's Incoming Webhooks, however, expect a specific, flat JSON format (e.g., `{"text": "..."}`).

If we connect SonarQube directly to Mattermost without a middleware translator, Mattermost will receive the signal but may fail to render it meaningfully (or reject it entirely as malformed). While there are third-party plugins that solve this, in our "First Principles" architecture, we have chosen a more robust pattern: **The Jenkins Relay**.

As we configured in the `Jenkinsfile` (Chapter 7), we allow Jenkins—which understands both the build context and the SonarQube result—to format and send the rich, color-coded alert to Mattermost.

However, we still provide the following script, **The Messenger**, to establish the direct link. This is useful if you intend to deploy a middleware adapter later or if you want to inspect the raw SonarQube payloads for debugging purposes.

Create this file at `~/Documents/FromFirstPrinciples/articles/0011_cicd_part07_mattermost/07-connect-sonarqube.py`.

```python
#!/usr/bin/env python3

import os
import json
import urllib.request
import urllib.parse
import urllib.error
import base64
import sys
from pathlib import Path

# --- Configuration ---
ENV_FILE = Path(os.environ.get("HOME")) / "cicd_stack" / "cicd.env"
# SonarQube runs on HTTP internally (Article 10 architecture)
SONAR_URL = "http://sonarqube.cicd.local:9000"
WEBHOOK_NAME = "Mattermost"

def load_env():
    if not ENV_FILE.exists():
        print(f"❌ Error: {ENV_FILE} not found.")
        sys.exit(1)

    with open(ENV_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip().strip('"\'')

def make_request(url, method="GET", data=None, token=None):
    # SonarQube uses Basic Auth with Token as username, empty password
    auth_str = f"{token}:"
    b64_auth = base64.b64encode(auth_str.encode()).decode()

    headers = {
        "Authorization": f"Basic {b64_auth}",
        # SonarQube requires form-encoded data for these endpoints
        "Content-Type": "application/x-www-form-urlencoded"
    }

    if data:
        encoded_data = urllib.parse.urlencode(data).encode("utf-8")
    else:
        encoded_data = None

    print(f"   [DEBUG] Request: {method} {url}")
    if data: print(f"   [DEBUG] Payload: {data}")

    req = urllib.request.Request(url, headers=headers, data=encoded_data, method=method)

    try:
        with urllib.request.urlopen(req) as response:
            body = response.read().decode()
            print(f"   [DEBUG] Response {response.status}: {body}")

            if response.status == 204: # No Content
                return None
            return json.loads(body)

    except urllib.error.HTTPError as e:
        print(f"   ⛔ HTTP Error {e.code}: {e.reason}")
        try:
            err_body = e.read().decode()
            print(f"      [DEBUG] Error Body: {err_body}")
        except:
            pass
        sys.exit(1)
    except Exception as e:
        print(f"   ❌ Unexpected Error: {e}")
        sys.exit(1)

def main():
    load_env()
    token = os.getenv("SONAR_ADMIN_TOKEN") # Generated in Art 10
    webhook_url = os.getenv("SONAR_MATTERMOST_WEBHOOK") # Generated in Step 04

    print(f"--- Connecting SonarQube to Mattermost ---")

    if not token:
        print("❌ Error: SONAR_ADMIN_TOKEN not found in cicd.env. (Run Art 10 setup?)")
        sys.exit(1)
    if not webhook_url:
        print("❌ Error: SONAR_MATTERMOST_WEBHOOK not found in cicd.env. (Run Step 04?)")
        sys.exit(1)

    # 1. Check existing webhooks to ensure Idempotency
    print(f"   🔎 Checking existing webhooks...")
    # The 'list' endpoint returns a JSON object with a 'webhooks' array
    webhooks_resp = make_request(f"{SONAR_URL}/api/webhooks/list", token=token)

    exists = False
    for hook in webhooks_resp.get("webhooks", []):
        if hook["name"] == WEBHOOK_NAME:
            exists = True
            print(f"   ℹ️  Webhook '{WEBHOOK_NAME}' already exists.")
            break

    # 2. Create Webhook if missing
    if not exists:
        print(f"   Creating webhook '{WEBHOOK_NAME}'...")
        params = {
            "name": WEBHOOK_NAME,
            "url": webhook_url
        }
        make_request(f"{SONAR_URL}/api/webhooks/create", method="POST", data=params, token=token)
        print(f"   ✅ Webhook created.")

    print(f"   ✅ Connection verified. Quality Gate alerts will go to #alerts.")
    print("[SUCCESS] SonarQube integration complete.")

if __name__ == "__main__":
    main()
```

## 9.4 The Integrator (`08-configure-plugins.py`)

We are now in the final phase of wiring the Library (GitLab).

In **Section 9.2**, we manually created the OAuth Application in GitLab and obtained the **Application ID** and **Secret**. However, Mattermost doesn't know these secrets yet.

Before running this script, you **must** update your `cicd.env` file with the values you copied from the GitLab UI.

**Pre-Requisite: Update Environment**
Open `~/cicd_stack/cicd.env` and append the following lines (replace the placeholders with your actual secrets):

```bash
GITLAB_OAUTH_ID="<paste_application_id_here>"
GITLAB_OAUTH_SECRET="<paste_secret_here>"
```

Now we run **The Integrator**. This script uses `mmctl` to inject these secrets into the Mattermost GitLab Plugin configuration, effectively "logging in" the server to GitLab.

Create this file at `~/Documents/FromFirstPrinciples/articles/0011_cicd_part07_mattermost/08-configure-plugins.py`.

```python
#!/usr/bin/env python3

import subprocess
import os
import sys
from pathlib import Path

# --- Configuration ---
CICD_ROOT = Path(os.environ.get("HOME")) / "cicd_stack"
ENV_FILE = CICD_ROOT / "cicd.env"
CONTAINER_NAME = "mattermost"
# Base command for mmctl via socket
MMCTL = ["docker", "exec", "-i", CONTAINER_NAME, "mmctl", "--local"]

def load_env():
    """Reads cicd.env into a dictionary."""
    if not ENV_FILE.exists():
        print(f"❌ Error: {ENV_FILE} not found.")
        sys.exit(1)

    env_vars = {}
    with open(ENV_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                env_vars[key.strip()] = value.strip().strip('"\'')
    return env_vars

def set_config(path, value):
    """Sets a config value using mmctl and prints output."""
    if value is None:
        print(f"   ⚠️  Skipping {path} (Value is missing/None)")
        return

    # mmctl config set <path> <value>
    cmd = MMCTL + ["config", "set", path, str(value)]

    try:
        # Capture stdout and stderr to print them
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"   ✅ Set {path}")

        # Print actual output from the tool if it exists
        if result.stdout.strip():
            print(f"      > {result.stdout.strip()}")
        if result.stderr.strip():
            print(f"      > {result.stderr.strip()}")

    except subprocess.CalledProcessError as e:
        print(f"   ❌ Failed to set {path}")
        print(f"      Exit Code: {e.returncode}")
        if e.stdout: print(f"      [STDOUT]: {e.stdout.strip()}")
        if e.stderr: print(f"      [STDERR]: {e.stderr.strip()}")

def main():
    print("--- Configuring Mattermost Plugins via CLI ---")
    secrets = load_env()

    # --- 1. GitLab Plugin Configuration ---
    # Plugin ID: com.github.manland.mattermost-plugin-gitlab
    print("   🔌 Configuring GitLab Plugin...")

    # We use the exact keys seen in your config.json
    base_path = "PluginSettings.Plugins.com.github.manland.mattermost-plugin-gitlab"

    # Required Secrets
    gitlab_url = "https://gitlab.cicd.local:10300"
    oauth_id = secrets.get("GITLAB_OAUTH_ID")
    oauth_secret = secrets.get("GITLAB_OAUTH_SECRET")
    webhook_secret = secrets.get("MATTERMOST_GITLAB_PLUGIN_SECRET")
    enc_key = secrets.get("MATTERMOST_GITLAB_PLUGIN_KEY")

    if not all([oauth_id, oauth_secret, webhook_secret, enc_key]):
        print("   ⚠️  Missing GitLab OAuth/Secret keys in cicd.env. Please check 01-setup script output.")
    else:
        set_config(f"{base_path}.gitlaburl", gitlab_url)
        set_config(f"{base_path}.gitlaboauthclientid", oauth_id)
        set_config(f"{base_path}.gitlaboauthclientsecret", oauth_secret)
        set_config(f"{base_path}.webhooksecret", webhook_secret)
        # Note: JSON key is 'encryptionkey', NOT 'atrestencryptionkey' based on the config structure
        set_config(f"{base_path}.encryptionkey", enc_key)

        # Feature Flags
        set_config(f"{base_path}.enableprivaterepo", "true")
        set_config(f"{base_path}.enablecodepreview", "public_private")

    # --- 2. Reload Config ---
    print("   🔄 Reloading Configuration...")
    try:
        reload_res = subprocess.run(MMCTL + ["config", "reload"], check=True, capture_output=True, text=True)
        print("   ✅ Config Reloaded.")
        if reload_res.stdout: print(f"      > {reload_res.stdout.strip()}")
    except subprocess.CalledProcessError as e:
        print(f"   ❌ Failed to reload config: {e.stderr}")

    print("[SUCCESS] Plugin configuration complete.")

if __name__ == "__main__":
    main()
```

### Deconstructing the Integrator

**1. Granular Configuration Targeting**
The Mattermost GitLab plugin is not a "first-party" plugin in the same way `focalboard` is. It lives under the long namespace `com.github.manland.mattermost-plugin-gitlab`. The script builds the config path dynamically: `PluginSettings.Plugins.com.github.manland...`.

**2. The Secrets Injection**
We inject four critical secrets:

* `gitlaboauthclientid` & `secret`: For authenticating users via the Sidebar.
* `webhooksecret`: For verifying that incoming webhooks are actually from GitLab (preventing spoofing).
* `encryptionkey`: For encrypting the user access tokens stored in the database.

**3. The Config Reload**
Unlike the Jenkins plugin installation (which required enabling/disabling), configuration changes via `config set` are often cached. We force a `config reload` command at the end to ensure the server picks up the new OAuth settings immediately without requiring a full container restart.

## 9.5 Verification: The Sidebar and the Alarm

We have wired the Library (GitLab) and the Inspector (SonarQube). Now we must confirm that the signals are flowing correctly.

### Part 1: The Library (GitLab Sidebar)

We have configured the server-side OAuth secrets. Now, just like with Jenkins, every user must perform a one-time handshake to link their Mattermost identity to their GitLab identity.

1.  **The Handshake:**
    Go to any channel (e.g., **\#town-square**) and type:

    ```bash
    /gitlab connect
    ```

2.  **The Authorization:**
    The bot will reply with a private link. Click it.

    * You will be redirected to `gitlab.cicd.local`.
    * If you are already logged in to GitLab, the authorization happens instantly.
    * You will be redirected back to Mattermost with a success message: *"You have successfully connected your GitLab account."*

3.  **The Sidebar:**
    Look at the **Right Sidebar** of your Mattermost interface. It is always visible.
    You should see a GitLab section that reflects your status:

    > **GitLab**
    > Signed in as: **root** (or your user)

    If you see "There are no GitLab subscriptions available in this channel," that is normal for a generic channel like `#town-square`. It simply means we haven't linked this specific chat channel to a specific git repository for commit broadcasts (which is what we used the Webhook for in Section 9.1). The critical part is that it recognizes *you*.

### Part 2: The Alarm (Quality Gate Failure)

Now we test the "Red Phone." We want to verify that if the Inspector (SonarQube) detects a violation, the alarm rings specifically in **\#alerts**, not just the general **\#builds** channel.

1.  **Verify the Rigging:**

    * Log in to **SonarQube** (`http://sonarqube.cicd.local:9000`).
    * Navigate to **Quality Gates**.
    * Ensure the **"Fail Hard"** gate (created in Article 10) is active.
    * Confirm the **Coverage** condition is set to **100%**.
    * *Note: Our `0004_std_lib_http_client` currently has \~94% coverage, so this guarantees a failure.*

2.  **Trigger the Build:**
    Go to **\#builds** in Mattermost and use your command power:

    ```bash
    /jenkins build articles/0004_std_lib_http_client/main
    ```

3.  **The Observation:**

    * **\#builds channel:** You will see the "Build Queued" confirmation.

    * *Wait approx. 2 minutes for the analysis...*

    * **\#alerts channel:** Suddenly, a notification appears here.

      > ⛔ **Quality Gate Failed**: ERROR
      > `http://sonarqube.cicd.local:9000/dashboard?id=...`

    * **\#builds channel:** Shortly after, the final verdict appears:

      > ❌ **Build Failed**

This confirms our routing logic is active. The general population in `#builds` sees that the build died, but the specific *reason* (Quality Gate Failure) is routed to `#alerts`, where the QA team or senior engineers would be subscribed.

# Chapter 10: Conclusion - The Command Center

## 10.1 The Echo Test (Verifying the Radio Tower)

We have verified that messages flow from our servers to our devices. Now, we must verify that high-bandwidth media can flow between our devices, traversing the treacherous "Double NAT" landscape we navigated in Chapter 4.

We built a **Coturn Radio Tower** to bridge the gap between the Docker internal network and the physical LAN. It is time to test if the tower is broadcasting.

**The Test Protocol:**
1.  **The Host:** On your desktop browser, navigate to the **#town-square** channel. Click the **Call** icon (phone handset) in the header to start a call. Grant camera and microphone permissions.
2.  **The Client:** On your Android device (connected to WiFi), open the **Mattermost App**. Navigate to **#town-square**. You should see a banner: *"Call in progress. Tap to join."*
3.  **The Connection:** Tap **Join**.

**The Moment of Truth:**
If the screen remains black or says "Reconnecting...", the UDP packets are being dropped by a firewall or misconfigured NAT.
If you see video from both devices and hear audio (likely with a screeching feedback loop because you are in the same room—**mute your mics quickly!**), then the Radio Tower is operational.

This success confirms that our "Host Mode" deployment of Coturn (`02-deploy-coturn.sh`) is successfully relaying UDP packets from your phone, through the host's physical interface, into the Mattermost container. We have achieved peer-to-peer style communication in a containerized environment.

## 10.2 The Architecture of ChatOps

With the video link established, take a step back and look at what we have built.

Before this article, managing our CI/CD pipeline was a game of "Tab Fatigue." You wrote code in an IDE. You pushed it. You switched to a browser tab to check GitLab. You switched to another tab to watch Jenkins. You clicked through to SonarQube to check for code smells. You were constantly **pulling** information from the system.

We have inverted this model. We have moved to a **Push-based** architecture.

* **The Factory (Jenkins)** pushes status updates to us.
* **The Inspector (SonarQube)** pushes alarms to us.
* **The Library (GitLab)** pushes merge requests to us.

We no longer poll the infrastructure; the infrastructure reports to us. The chat window has become the single pane of glass for the entire software lifecycle. We have achieved **ChatOps**: the practice of connecting people, tools, and processes into a transparent workflow.

## 10.3 Sovereign Infrastructure

Perhaps the greater achievement is *how* we built it.

We did not spin up a SaaS instance of Slack or Discord. We did not rely on cloud-hosted relays. We built a fully sovereign communications platform on our own hardware, running on a standard Linux kernel.

More importantly, we rejected the easy path of "Click-Ops." We did not manually configure ten different integration settings in the web UI. We wrote software to configure our software.

* **`01-03`**: Deployed the core infrastructure.
* **`04, 06, 07`**: Wired the webhooks and integrations programmatically.
* **`05, 08, 09`**: Injected configuration and plugins into running containers.

If we were to wipe our `mattermost` container today, we could restore the entire city—every channel, every bot, every permission scheme—simply by re-running our scripts. This is the discipline of **Infrastructure as Code**.

We also conquered the "Mobile Frontier." By manually establishing our own Certificate Authority and installing it on Android, we proved that you do not need Let's Encrypt or a public domain name to have secure, encrypted mobile connectivity.

## 10.4 The Road Ahead: The Noise Problem

Our "Digital City" is now bustling. We have GitLab managing code, Jenkins building binaries, SonarQube inspecting quality, and Mattermost coordinating communications.

But a bustling city generates noise.

Currently, if a build fails mysteriously, you have to SSH into the host and run `docker logs jenkins`. If Nginx throws a 502 error, you are grepping through `/var/log/nginx`. As we add more services, our logs are becoming fragmented, scattered across different containers and file systems. We have built a powerful engine, but we lack a centralized dashboard to monitor its internal health.

In the next and final article of this series, we will tackle the **Observability** layer. We will deploy the **ELK Stack** (Elasticsearch, Logstash, Kibana) to ingest, parse, and visualize the massive stream of data our city is generating, turning raw noise into actionable intelligence.

The command center is open. Now, let's turn on the radar.