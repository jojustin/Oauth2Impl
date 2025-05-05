from oauthlib.oauth2 import RequestValidator, AuthorizationCodeGrant, BearerToken, TokenEndpoint, Server
from datetime import datetime, timedelta
import sqlite3
import secrets
from oauthlib.common import generate_token

DB = 'db.sqlite'

class SQLiteValidator(RequestValidator):
    def __init__(self):
        print("[DEBUG] SQLiteValidator instance created")
        super().__init__()
    def _conn(self):
        return sqlite3.connect(DB)

    def client_authentication_required(self, request):
        return True

    def authenticate_client(self, request):
        client_id = request.client_id
        client_secret = request.client_secret

        if not client_id or not client_secret:
            return False

        with self._conn() as conn:
            row = conn.execute(
                "SELECT client_id, client_secret FROM clients WHERE client_id=?",
                (client_id,)
            ).fetchone()

        if row and row[1] == client_secret:
            request.client = type('Client', (object,), {'client_id': client_id})()
            return True

        return False



    def validate_client_id(self, client_id, request):
        with self._conn() as conn:
            row = conn.execute("SELECT 1 FROM clients WHERE client_id=?", (client_id,)).fetchone()
        print(f"[DEBUG] Validating client_id: {client_id} => {bool(row)}")
        return row is not None

    def validate_redirect_uri(self, client_id, redirect_uri, request):
        with self._conn() as conn:
            row = conn.execute("SELECT redirect_uri FROM clients WHERE client_id=?", (client_id,)).fetchone()
        if not row:
            return False
        valid_uris = [uri.strip() for uri in row[0].split(',')]
        is_valid = redirect_uri.strip() in valid_uris
        print(f"[DEBUG] validate_redirect_uri: redirect_uri={redirect_uri}, valid={is_valid}")
        return redirect_uri.strip() in valid_uris

    def get_default_redirect_uri(self, client_id, request):
        with self._conn() as conn:
            row = conn.execute("SELECT redirect_uri FROM clients WHERE client_id=?", (client_id,)).fetchone()
        return row[0] if row else None

    def validate_response_type(self, client_id, response_type, client, request):
        request.user = "demo_user"
        print(f"[DEBUG] validate_response_type: client_id={client_id}, response_type={response_type}")
        return response_type == 'code'

    def save_authorization_code(self, client_id, code, request):
        with self._conn() as conn:
            conn.execute("INSERT INTO auth_codes (code, client_id, redirect_uri, user, scope) VALUES (?, ?, ?, ?, ?)", (
                code['code'], client_id, request.redirect_uri, request.user, ' '.join(request.scopes)
            ))
            conn.commit()

    def validate_code(self, client_id, code, client, request):
        with self._conn() as conn:
            row = conn.execute("SELECT user, scope FROM auth_codes WHERE code=? AND client_id=?", (code, client_id)).fetchone()
        if row:
            request.user, scope = row
            request.scopes = scope.split()
            return True
        return False

    def get_default_scopes(self, client_id, request):
        return ['read']

    def validate_grant_type(self, client_id, grant_type, client, request):
        with self._conn() as conn:
            row = conn.execute("SELECT grant_types FROM clients WHERE client_id=?", (client_id,)).fetchone()
        return grant_type in row[0].split(',') if row else False

    def save_bearer_token(self, token, request):
        from datetime import datetime, timedelta
        with self._conn() as conn:
            expires_at = datetime.utcnow() + timedelta(seconds=token['expires_in'])
            conn.execute("INSERT INTO tokens (access_token, refresh_token, client_id, user, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?)", (
                token['access_token'], token.get('refresh_token'),
                request.client_id, getattr(request, 'user', None),
                ' '.join(request.scopes), expires_at
            ))
            conn.commit()

    def get_original_scopes(self, refresh_token, request):
        return ['read']

    def validate_refresh_token(self, refresh_token, client, request):
        return True

    def validate_scopes(self, client_id, scopes, client, request):
        return True

    def validate_user(self, username, password, client, request):
        return True
    
    def save_token(self, token, request):
        print("[DEBUG] save_token called")
        self.save_bearer_token(token, request)  # ✅ delegate to your existing method
    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request):
        # Optional in OAuth2 spec but required by oauthlib for strict checks
        with self._conn() as conn:
            row = conn.execute(
                "SELECT redirect_uri FROM auth_codes WHERE code=? AND client_id=?",
                (code, client_id)
            ).fetchone()

        if row:
            return row[0] == redirect_uri
        return False

    def invalidate_authorization_code(self, client_id, code, request):
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM auth_codes WHERE code=? AND client_id=?",
                (code, client_id)
            )
            conn.commit()

    def validate_bearer_token(self, token, scopes, request):
        with self._conn() as conn:
            row = conn.execute(
                "SELECT user, scope, expires_at FROM tokens WHERE access_token=?",
                (token,)
            ).fetchone()

        if not row:
            return False

        user, scope_str, expires_at_str = row
        expires_at = datetime.strptime(expires_at_str, "%Y-%m-%d %H:%M:%S.%f")

        if datetime.utcnow() > expires_at:
            return False

        request.user = user
        request.scopes = scope_str.split()
        return True

    def __getattribute__(self, name):
        try:
            return super().__getattribute__(name)
        except AttributeError:
            print(f"[DEBUG] OAuthLib tried to call unimplemented method: {name}")
            raise NotImplementedError(f"{name} must be implemented in RequestValidator")
def register_client(client_id, client_secret, redirect_uri, grant_types):
    with sqlite3.connect(DB) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO clients (client_id, client_secret, redirect_uri, grant_types) VALUES (?, ?, ?, ?)",
            (client_id, client_secret, redirect_uri, grant_types)
        )
        conn.commit()

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_types": grant_types
    }


validator = SQLiteValidator()

# ✅ Create BearerToken generator that knows how to save tokens
bearer = BearerToken(
    request_validator=validator,
    token_generator=generate_token,
    expires_in=None,
    refresh_token_generator=generate_token
)

# ✅ Register the grant type
auth_grant = AuthorizationCodeGrant(request_validator=validator)

# ✅ Set up the token endpoint
token_endpoint = TokenEndpoint(
    default_grant_type='authorization_code',
    grant_types={'authorization_code': auth_grant},
    default_token_type=bearer
)

# ✅ Create a server with token endpoint and authorization logic
oauth_server = Server(request_validator=validator, token_endpoint=token_endpoint)
