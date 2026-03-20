import os
import secrets
import hashlib, base64, urllib.parse
from datetime import datetime, timedelta
from functools import wraps

import jwt, requests
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, g
from flask_session import Session
from dotenv import load_dotenv

load_dotenv()



app = Flask(__name__)
# ký session Flask
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
#ký dữ liệu session/state
app.config['SESSION_SECRET'] = os.getenv('SESSION_SECRET')
# định danh app với Google 
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')


APP_URL = os.getenv('APP_URL')

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True  
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
Session(app)

GOOGLE_CONFIG = {
    'client_id': GOOGLE_CLIENT_ID,
    'client_secret': GOOGLE_CLIENT_SECRET,
    'auth_uri': 'https://accounts.google.com/o/oauth2/v2/auth',
    'token_uri': 'https://oauth2.googleapis.com/token',
    'issuer': 'https://accounts.google.com',
    'userinfo_uri': 'https://openidconnect.googleapis.com/v1/userinfo',
    'redirect_uri' : APP_URL + '/auth/callback',
    'scope': 'openid email profile'
}
#Tạo PKCE 
def generate_code_verifier():
    verifier = secrets.token_urlsafe(64)
    return verifier[:128]
#Gửi lên google trong request authorization -> xác thực code verifier
def generate_code_challenge(verifier):
    verifier_bytes = verifier.encode('utf-8')
    sha256_hash = hashlib.sha256(verifier_bytes).digest()
    challenge = base64.urlsafe_b64encode(sha256_hash).decode('utf-8')
    challenge = challenge.replace('=', '')

    return challenge

#nonce - replay attack 
def generate_nonce():
    return secrets.token_urlsafe(32)

#state - CSRF
def generate_state():
    return secrets.token_urlsafe(32)

# tạo jwt token (tạo session token riêng để xác thực người dùng sau khi đã xác thực với Google)
def create_jwt_token(user_info, nonce):
    now = datetime.utcnow()
    payload = {
        'sub': user_info.get('sub'),
        'email': user_info.get('email'),
        'name': user_info.get('name'),
        'nonce': nonce,
        'iat': now,
        'exp': now + timedelta(hours=24),
        'iss': APP_URL,
        'aud': GOOGLE_CONFIG['client_id']
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token 

#Xác thực JWT token của app - kiểm tra tính hợp lệ của session
def verify_jwt_token(token):
    try:
        payload = jwt.decode(token,app.config['SECRET_KEY'], algorithms=['HS256'], issuer=APP_URL, audience=GOOGLE_CONFIG['client_id'])
        return payload
    except jwt.InvalidTokenError as e:
        print(f"JWT verification failed: {e}")
        return None
    
#Lấy public key từ Google để xác thực chữ ký số của Google
def get_google_public_keys():
    try:
        response = requests.get('https://www.googleapis.com/oauth2/v3/certs')
        return response.json().get('keys',[])
    except Exception as e:
        print(f"Failed to get Google public keys: {e}")
        return []

#Đảm bảo token thực sự đến Google và không bị giả mạo
def verify_google_jwt(id_token):
    try: 
        public_keys = get_google_public_keys()
        header = jwt.get_unverified_header(id_token)
        kid = header.get('kid')

        key_data = next((k for k in public_keys if k['kid'] == kid), None)
        if not key_data:
            print(f"Key ID {kid} not found in Google public keys")
            return None
        
        from jwt.algorithms import RSAAlgorithm
        public_key = RSAAlgorithm.from_jwk(key_data)

        payload = jwt.decode(id_token, public_key, algorithms=['RS256'], issuer='https://accounts.google.com', audience=GOOGLE_CONFIG['client_id'])
        return payload 
    except jwt.ExpiredSignatureError:
        print("Google JWT has expired")
        return None
    except jwt.InvalidTokenError as e:
        print(f"Google JWT verification failed: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error verifying Google JWT: {e}")
        return None

#Chỉ cho phép người dùng đã đăng nhập truy cập  
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('jwt_token')

        if not token:
            return redirect(url_for('index'))
        
        payload = verify_jwt_token(token)
        if not payload:
            print("JWT verification failed in login_required")
            session.clear()
            return redirect(url_for('index'))
        
        stored_nonce = session.get('nonce')
        if not stored_nonce or payload.get('nonce') != stored_nonce:
            print("Nonce mismatch in login_required")
            session.clear()
            return redirect(url_for('index'))
        
        auth_start = session.get('auth_start_time')
        if auth_start:
            now = datetime.utcnow().timestamp()
        if now - auth_start > 3600:  # 1 giờ
            session.clear()
            return redirect(url_for('index'))
        
        g.user = payload
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/auth/login')
def login():
    #Xóa session cũ
    keys_to_remove = ['user', 'jwt_token', 'state', 'nonce', 'code_verifier']
    for key in keys_to_remove:
        session.pop(key, None)
    #Tạo PKCE, challenge, nonce, state
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)

    nonce = generate_nonce()
    state = generate_state()
    #Lưu vào session
    session['code_verifier'] = code_verifier
    session['nonce'] = nonce
    session['state'] = state
    session['auth_start_time'] = datetime.utcnow().timestamp()

    print(f"Login started - nonce: {nonce}, state: {state}")

    #xây dựng URL và chuyển hướng user đến Google
    params = {
        'client_id': GOOGLE_CONFIG['client_id'],
        'redirect_uri': GOOGLE_CONFIG['redirect_uri'],
        'response_type': 'code',
        'scope': GOOGLE_CONFIG['scope'],
        'state': state,
        'nonce': nonce,  
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'access_type': 'offline',  
        'prompt': 'consent'  
    }
    auth_url = f"{GOOGLE_CONFIG['auth_uri']}?{urllib.parse.urlencode(params)}"
    return redirect(auth_url)

@app.route('/auth/callback')
def callback():
    #Kiểm tra state 
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    
    if error:
        return f"Error from Google: {error}", 400
    stored_state = session.get('state')
    if not stored_state:
        return "No state found in session", 400

    if state != stored_state:
        print(f"State mismatch: received={state}, stored={stored_state}")
        return "Invalid state parameter", 400
    code_verifier = session.get('code_verifier')
    if not code_verifier:
        return "Missing code verifier", 400
    
    # Lấy code trao đổi với Google để nhận tokens
    token_data = {
        'code': code,
        'client_id': GOOGLE_CONFIG['client_id'],
        'client_secret': GOOGLE_CONFIG['client_secret'],
        'redirect_uri': GOOGLE_CONFIG['redirect_uri'],
        'grant_type': 'authorization_code',
        'code_verifier': code_verifier  
    }

    try: 
        token_response = requests.post(GOOGLE_CONFIG['token_uri'], data=token_data, headers = {'Content-Type': 'application/x-www-form-urlencoded'})
        token_response.raise_for_status()
        tokens = token_response.json()

        id_token = tokens.get('id_token')
        if not id_token:
            return "No ID Token recevied",400
        
        print('ID Token received')

        google_payload = verify_google_jwt(id_token)
        if not google_payload:
            return "Invalid ID Token - verification failed", 400
        
        print(f"Google JWT verified successfully: {google_payload.get('email')}")

        received_nonce = google_payload.get('nonce')
        stored_nonce = session.get('nonce')
        
        if not stored_nonce:
            return "No nonce found in session", 400
        
        if not received_nonce or received_nonce != stored_nonce:
            print(f"Nonce mismatch: received={received_nonce}, stored={stored_nonce}")
            return "Invalid nonce - possible replay attack", 400

        print("Nonce verified successfully")
        # Lấy user info
        userinfo_response = requests.get(
            GOOGLE_CONFIG['userinfo_uri'],
            headers={'Authorization': f"Bearer {tokens['access_token']}"}
        )
        userinfo_response.raise_for_status()
        user_info = userinfo_response.json()
        
        # Tạo JWT token tự định nghĩa
        jwt_token = create_jwt_token(user_info, stored_nonce)
        
        # Lưu thông tin vào session
        session['jwt_token'] = jwt_token
        session['user'] = user_info
        session.pop('code_verifier', None)  # Xóa PKCE verifier
        session.pop('state', None)  # Xóa state
        #Redirect đến profile
        print(f"Login successful for user: {user_info.get('email')}")
        return redirect(url_for('profile'))
        
    except requests.exceptions.RequestException as e:
        print(f"Token exchange failed: {e}")
        return f"Token exchange failed: {e}", 500
    except Exception as e:
        print(f"Unexpected error in callback: {e}")
        return f"An error occurred: {e}", 500

@app.route('/profile')
@login_required
def profile():
    user = session.get('user')
    print(user)
    jwt_token = session.get('jwt_token')
    print(jwt_token)
    try:
        jwt_payload = verify_jwt_token(jwt_token)
        print(jwt_payload)
    except:
        jwt_payload = {"error": "Could not decode JWT"}
    return render_template('profile.html', user=user, jwt_token=jwt_token, jwt_payload=jwt_payload)

@app.route('/auth/logout')
def logout():
    user_email = session.get('user', {}).get('email', 'Unknown')
    session.clear()
    return redirect(url_for('index'))

@app.route('/verify-token')
def verify_token_endpoint():
    token = session.get('jwt_token')
    if not token: 
        return jsonify({'valid': False, 'error': 'No token'}), 401
    payload = verify_jwt_token(token)
    if payload:
        return jsonify({'valid': True, 'payload': payload})
    else:
        return jsonify({'valid': False, 'error': 'Invalid token'}), 401
    
@app.route('/debug-session')
def debug_session():
    if app.debug:
        session_data = {
            'has_jwt': 'jwt_token' in session,
            'has_user': 'user' in session,
            'has_nonce': 'nonce' in session,
            'session_keys': list(session.keys()),
            'session_id': request.cookies.get('session')
        }
        return jsonify(session_data)
    return "Not available in production", 404


if __name__ == '__main__':
    

    app.run(
            host='0.0.0.0',
            port=5000,
            debug=True
        )