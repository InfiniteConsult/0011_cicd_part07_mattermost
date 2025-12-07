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