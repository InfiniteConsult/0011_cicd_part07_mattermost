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
ADMIN_USER = "warren.jitsing" # Ensure this user exists via UI/SSO

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

    # 3. Create Jenkins Bot
    print(f"--- Configuring Jenkins Bot ---")

    # 3a. Ensure Password Exists
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

    if "JENKINS_MATTERMOST_TOKEN" in env_content:
        print("   ℹ️  JENKINS_MATTERMOST_TOKEN already exists in cicd.env. Skipping.")
    else:
        bot_email = "jenkins-bot@cicd.local"
        bot_user = "jenkins-bot"

        print("   Ensuring Jenkins Bot User exists...")
        run_mmctl(["user", "create", "--email", bot_email, "--username", bot_user, "--password", bot_password], allow_fail=True)

        run_mmctl(["user", "verify", bot_user], allow_fail=True)
        run_mmctl(["team", "users", "add", TEAM_NAME, bot_user], allow_fail=True)

        print("   Generating Access Token...")
        token_res = run_mmctl(["token", "generate", bot_user, "Jenkins Integration"])

        if token_res:
            jenkins_token = token_res.get("token", "")
            if jenkins_token:
                append_to_env("JENKINS_MATTERMOST_TOKEN", jenkins_token)
                env_content += f"\nJENKINS_MATTERMOST_TOKEN={jenkins_token}"
        else:
            print("   ⚠️  Failed to generate token (or output was empty).")

    # 4. Create SonarQube Webhook (#alerts)
    print(f"--- Configuring SonarQube Webhook ---")

    if "SONAR_MATTERMOST_WEBHOOK" in env_content:
        print("   ℹ️  SONAR_MATTERMOST_WEBHOOK already exists in cicd.env. Skipping.")
    else:
        print("   Creating Incoming Webhook for #alerts...")
        # FIX: Use fully qualified channel name: engineering:alerts
        hook_res = run_mmctl(["webhook", "create-incoming", "--user", ADMIN_USER, "--channel", f"{TEAM_NAME}:alerts", "--display-name", "SonarQube", "--description", "Quality Gate Alerts"])

        if hook_id := hook_res.get("id"):
            webhook_url = f"https://mattermost.cicd.local:8065/hooks/{hook_id}"
            append_to_env("SONAR_MATTERMOST_WEBHOOK", webhook_url)
            env_content += f"\nSONAR_MATTERMOST_WEBHOOK={webhook_url}"

    # 5. Create GitLab Webhook (#code-reviews)
    print(f"--- Configuring GitLab Webhook ---")

    if "MATTERMOST_CODE_REVIEW_WEBHOOK" in env_content:
        print("   ℹ️  MATTERMOST_CODE_REVIEW_WEBHOOK already exists in cicd.env. Skipping.")
    else:
        print("   Creating Incoming Webhook for #code-reviews...")
        # FIX: Use fully qualified channel name: engineering:code-reviews
        hook_res = run_mmctl(["webhook", "create-incoming", "--user", ADMIN_USER, "--channel", f"{TEAM_NAME}:code-reviews", "--display-name", "GitLab", "--description", "Commit and Merge Request Events"])

        if hook_id := hook_res.get("id"):
            webhook_url = f"https://mattermost.cicd.local:8065/hooks/{hook_id}"
            append_to_env("MATTERMOST_CODE_REVIEW_WEBHOOK", webhook_url)

    print("\n✅ Configuration Complete.")
    print("   Restart Jenkins/SonarQube to pick up new secrets.")

if __name__ == "__main__":
    main()