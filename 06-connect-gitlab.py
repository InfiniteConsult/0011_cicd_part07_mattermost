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