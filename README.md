# Running Server 
python3 -m venv venv

source venv/bin/activate
pip install Flask oauthlib requests

python app.py

# Running Client 
python3 -m venv venv

source venv/bin/activate

pip install requests

python oauth_client.py


# Authorizing the user
**Incase to try via the curl (to test)** - curl -X POST http://localhost:5050/authorize -d "client_id=client_id_123" -d "redirect_uri=http://localhost:5050/callback" -d "response_type=code" -d "scope=read" -v


**For checking the sqllite tables -**
sqlite3 db.sqlite
.tables
sqlite> SELECT client_id, client_secret FROM oauth2_client;

## Setup Phase

**Register Client with Authorization Server by calling /register endpoint with:**
* client_id (e.g., client_id_123)
* client_secret (e.g., secret_abc)
* redirect_uri (e.g., http://localhost:5050/callback)
*  grant_types: "authorization_code"

The server stores this info in the DB for validation during future OAuth requests.

## User (Resource Owner) - Authorization Flow

1. User Logs In (via /login) by 
   * providing username/password (or via SSO in real systems)
   * Server sets session["user"] = "demo_user"

2. Client App Requests Authorization
   * Sends a POST to /authorize with:
     * client_id
     * redirect_uri
     * response_type=code
     * scope=read

3. Server Verifies and Redirects
   * If user is logged in and client_id & redirect_uri are valid:
   * Server creates an authorization_code (e.g., abc123)
   * Responds with a redirect to: http://client-app/callback?code=abc123

## Client App Exchanges Code for Token

4. Client Sends Token Request
   * POST to /token with:
     * grant_type=authorization_code
     * code=abc123
     * client_id, client_secret
     * redirect_uri

5. Server Validates Everything
    * Verifies code, client credentials, and redirect URI match
    * Issues:
      * access_token
      * (optional) refresh_token

## Client Uses Token to Access Protected Resource
6. Client Requests Protected Resource
   * Adds header: Authorization: Bearer <access_token>
   * Calls /protected
   * Server checks token validity using validate_bearer_token and returns data if valid

