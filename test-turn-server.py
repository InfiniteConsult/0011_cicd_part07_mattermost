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
