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
        # Note: JSON key is 'encryptionkey', NOT 'atrestencryptionkey' based on your config dump
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