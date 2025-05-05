from flask import Flask, request, redirect, jsonify, session, make_response
from oauth_provider import oauth_server, DB
import sqlite3
from oauth_provider import register_client
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)

@app.route('/authorize', methods=['POST'])
def authorize():
    try:
        user = session.get("user")
        if not user:
            return redirect(f"/login?next={request.url}")
        client_id = request.form.get("client_id")
        redirect_uri = request.form.get("redirect_uri")
        response_type = request.form.get("response_type")
        scope = request.form.get("scope", "read").split()

        print(f"[DEBUG] Received POST /authorize with: client_id={client_id}, redirect_uri={redirect_uri}, response_type={response_type}")

        if not all([client_id, redirect_uri, response_type]):
            return jsonify({"error": "Missing required parameters"}), 400

        uri = request.base_url
        headers = {}  # important: don't reuse request.headers
        body = request.form.to_dict(flat=True)
        body_str = '&'.join(f"{k}={v}" for k, v in body.items())
        credentials = {'user': user, 'scope': scope}

        # response = oauth_server.create_authorization_response(
        #     uri,
        #     http_method='POST',
        #     body=body_str,
        #     headers=headers,
        #     credentials=credentials
        # )

        response_headers, body, status = oauth_server.create_authorization_response(
            uri,
            http_method='POST',
            body=body_str,
            headers=headers,
            credentials=credentials
        )

        redirect_location = response_headers.get("Location")
        if not redirect_location:
            raise ValueError("Missing Location in OAuthLib response.")

        print(f"[DEBUG] Redirecting to: {redirect_location}")
        return redirect(redirect_location)

    except Exception as e:
        print(f"[ERROR] Exception in /authorize: {str(e)}")
        return jsonify({"error": "Server error", "details": str(e)}), 500

@app.route('/token', methods=['POST'])
def token():
    try:
        uri = request.url
        http_method = request.method
        body = request.form.to_dict(flat=True)
        body_str = '&'.join(f"{k}={v}" for k, v in body.items())
        
        headers = dict(request.headers)
        print(f"[DEBUG] /token body: {body_str}")

        response_headers, response_body, status = oauth_server.create_token_response(
            uri, http_method=http_method, body=body_str, headers=headers
        )

        flask_response = make_response(response_body, status)
        for k, v in response_headers.items():
            flask_response.headers[k] = v

        return flask_response

    except Exception as e:
        print(f"[ERROR] Exception in /token: {str(e)}")
        return jsonify({"error": "token exchange failed", "details": str(e)}), 500

@app.route('/protected')
def protected():
    auth = request.headers.get('Authorization', '')
    token = auth.replace('Bearer ', '')
    valid, req = oauth_server.verify_request(
        request.url, http_method='GET', body={}, headers=dict(request.headers)
    )

    if valid:
        return jsonify({"message": "Access granted", "user": req.user})

    return jsonify({"error": "Access denied"}), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    client_id = data.get('client_id') or secrets.token_urlsafe(16)
    client_secret = data.get('client_secret') or secrets.token_urlsafe(32)
    redirect_uri = data.get('redirect_uri')
    grant_types = data.get('grant_types', 'authorization_code')

    if not redirect_uri:
        return jsonify({"error": "redirect_uri is required"}), 400

    result = register_client(client_id, client_secret, redirect_uri, grant_types)
    return jsonify(result), 201

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        if username:
            session["user"] = username
            return redirect(request.args.get("next", "/"))
        return "Username is required", 400

    return '''
        <form method="post">
            Username: <input name="username" />
            <input type="submit" />
        </form>
    '''

if __name__ == '__main__':
    print(app.url_map)
    app.run(debug=True, port=5050)
