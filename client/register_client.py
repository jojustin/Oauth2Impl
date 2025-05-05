import requests

client_id = "client_id_123"
client_secret = "secret_abc"
redirect_uri = "http://localhost:5050/callback"
grant_types = "authorization_code,client_credentials"

response = requests.post("http://localhost:5050/register", json={
    "client_id": client_id,
    "client_secret": client_secret,
    "redirect_uri": redirect_uri,
    "grant_types": grant_types
})

print("Client registration response:")
print(response.status_code)
print(response.json())
