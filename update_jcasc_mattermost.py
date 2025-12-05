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