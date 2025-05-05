import requests
from urllib.parse import urlparse, parse_qs

# Config
client_id = "client_id_123"
client_secret = "secret_abc"
redirect_uri = "http://localhost:5050/callback"
auth_url = "http://localhost:5050/authorize"
token_url = "http://localhost:5050/token"
protected_url = "http://localhost:5050/protected"

# Step 1: POST to /authorize
print(f"\nStep 1: Requesting authorization code via POST...")
auth_response = requests.post(auth_url, data={
    "response_type": "code",
    "client_id": client_id,
    "redirect_uri": redirect_uri,
    "scope": "read"
}, allow_redirects=False)

# Step 2: Follow redirect and extract code
redirect_location = auth_response.headers.get('Location')
if not redirect_location:
    print("No redirect received. Authorization may have failed.")
    print("Response:", auth_response.text)
    exit(1)

parsed_url = urlparse(redirect_location)
code = parse_qs(parsed_url.query).get("code", [None])[0]
if not code:
    print("Authorization code not received.")
    exit(1)

# Fix malformed code value
code = code.strip().strip("'").strip('"').strip("}")
print(f"Authorization code received: {code}")
print(f"[DEBUG] Raw redirect: {redirect_location}")

# Step 3: Exchange authorization code for token
token_response = requests.post(token_url, data={
    "grant_type": "authorization_code",
    "code": code,
    "redirect_uri": redirect_uri,
    "client_id": client_id,
    "client_secret": client_secret
})

if token_response.status_code != 200:
    print("Failed to get token!")
    print("Status Code:", token_response.status_code)
    print("Raw response:", token_response.text)
    try:
        print("Parsed JSON:", token_response.json())
    except Exception as e:
        print("Could not parse JSON:", str(e))
    exit(1)
token_json = token_response.json()

access_token = token_json.get("access_token")
refresh_token = token_json.get("refresh_token")

# Step 4: Call protected endpoint
protected_response = requests.get(protected_url, headers={
    "Authorization": f"Bearer {access_token}"
})

print(f"\nProtected Resource Response:\n{protected_response.json()}")
print(f"Status Code: {protected_response.status_code}")
print(f"Raw Text:\n{protected_response.text}")
