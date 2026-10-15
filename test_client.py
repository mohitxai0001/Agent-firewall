import requests
import time

BASE_URL = "http://127.0.0.1:8000"

# 1. Create a Project and get an API key
print("Step 1: Registering project and generating API Key...")
project_res = requests.post(
    f"{BASE_URL}/v1/projects",
    json={
        "name": "Acme Autonomous Search Agent",
        "budget_limit": 0.000100,      # $0.0001 limit
        "max_steps_per_session": 3     # Kill after 3 calls
    }
)

project_data = project_res.json()
api_key = project_data["api_key"]
print(f"Project Created! Key: {api_key}\n")

# 2. Simulate agent calls using the Bearer Token
headers = {
    "Authorization": f"Bearer {api_key}",
    "X-Session-ID": "agent-auth-run-1"
}

payload = {
    "model": "gemini/gemini-3.1-flash-lite",
    "messages": [
        {"role": "user", "content": "Say 'Firewall verified' in two words."}
    ]
}

print("Step 2: Simulating authenticated agent loops...\n")
for i in range(1, 5):
    print(f"--- Attempting Call #{i} ---")
    res = requests.post(f"{BASE_URL}/v1/chat/completions", json=payload, headers=headers)
    
    if res.status_code == 200:
        reply = res.json()["choices"][0]["message"]["content"].strip()
        print(f"Status 200: Success -> {reply}\n")
    elif res.status_code == 429:
        print("Status 429: BLOCKED BY FIREWALL!")
        print(f"Reason: {res.json()['detail']}\n")
        break
    else:
        print(f"Error {res.status_code}: {res.text}\n")
        break
    time.sleep(1)