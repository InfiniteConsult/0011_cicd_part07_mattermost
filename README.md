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
