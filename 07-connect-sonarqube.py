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