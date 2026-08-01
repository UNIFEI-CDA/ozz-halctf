"""
TARGET-03: Flask API REST com SSTI e JWT bypass
Flag: flag{api_breaker} em /app/secret/flag.txt
Credencial: token JWT com bypass para acessar /admin
"""

from flask import Flask, request, jsonify, render_template_string
import jwt
import json
import os
import hashlib

app = Flask(__name__)
SECRET_KEY = "super_secret_key_2026"  # Fraco e previsível

# Flag
os.makedirs("/app/secret", exist_ok=True)
with open("/app/secret/flag.txt", "w") as f:
    f.write("flag{api_breaker_2026}")

# Credenciais para TARGET-04
DB_CREDS = {
    "mysql_internal": {
        "host": "10.0.0.40",
        "user": "root",
        "password": "MySQL_R00t_2026!",
        "note": "Use this to access the internal database"
    }
}

# Users database
USERS = {
    "admin": {"password": hashlib.sha256(b"admin2026").hexdigest(), "role": "admin"},
    "user1": {"password": hashlib.sha256(b"user1pass").hexdigest(), "role": "user"},
    "api_bot": {"password": hashlib.sha256(b"bot_token_2026").hexdigest(), "role": "service"},
}

# Products (fake data)
PRODUCTS = [
    {"id": 1, "name": "Widget A", "price": 29.99, "stock": 100},
    {"id": 2, "name": "Widget B", "price": 49.99, "stock": 50},
    {"id": 3, "name": "Premium Service", "price": 999.99, "stock": 10},
]

@app.route('/')
def index():
    return jsonify({
        "service": "SecureCorp API v3.2",
        "endpoints": {
            "GET /": "This page",
            "POST /auth/login": "Authenticate",
            "GET /auth/verify": "Verify token",
            "GET /products": "List products",
            "GET /products/<id>": "Get product",
            "GET /admin": "Admin panel (requires admin token)",
            "GET /admin/secrets": "View secrets (requires admin token)",
            "POST /render": "Template rendering service",
            "GET /health": "Health check",
            "GET /debug": "Debug info",
        },
        "docs": "/docs",
    })

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    user = USERS.get(username)
    
    if user and user['password'] == password_hash:
        # VULN: Weak JWT secret + algorithm confusion
        token = jwt.encode(
            {"user": username, "role": user['role'], "iat": 1234567890},
            SECRET_KEY,
            algorithm="HS256"
        )
        return jsonify({"token": token, "user": username, "role": user['role']})
    
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/auth/verify', methods=['GET'])
def verify_token():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return jsonify({"error": "No token provided"}), 401
    
    try:
        # VULN: Accepts 'none' algorithm
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256", "none"])
        return jsonify({"valid": True, "payload": payload})
    except jwt.InvalidTokenError as e:
        return jsonify({"valid": False, "error": str(e)}), 401

@app.route('/products')
def list_products():
    return jsonify({"products": PRODUCTS})

@app.route('/products/<int:product_id>')
def get_product(product_id):
    product = next((p for p in PRODUCTS if p['id'] == product_id), None)
    if product:
        return jsonify(product)
    return jsonify({"error": "Product not found"}), 404

@app.route('/admin')
def admin_panel():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return jsonify({"error": "Admin token required"}), 403
    
    try:
        # VULN: Accepts 'none' algorithm — bypass authentication
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256", "none"])
        if payload.get('role') != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        
        return jsonify({
            "message": "Welcome to admin panel",
            "secrets_endpoint": "/admin/secrets",
            "system_info": "/debug",
            "users": list(USERS.keys()),
        })
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 403

@app.route('/admin/secrets')
def admin_secrets():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return jsonify({"error": "Admin token required"}), 403
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256", "none"])
        if payload.get('role') != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        
        return jsonify({
            "flag": "flag{api_breaker_2026}",
            "db_credentials": DB_CREDS,
            "jwt_secret": SECRET_KEY,
        })
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 403

# VULN: Server-Side Template Injection
@app.route('/render', methods=['POST'])
def render():
    data = request.get_json() or {}
    template = data.get('template', 'Hello {{ name }}')
    name = data.get('name', 'World')
    
    # No sanitization — SSTI!
    try:
        result = render_template_string(template.replace('{{ name }}', name))
        return jsonify({"rendered": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "service": "api-v3.2"})

@app.route('/debug')
def debug():
    # VULN: Debug endpoint exposed
    return jsonify({
        "python_version": os.popen("python3 --version").read().strip(),
        "environment": dict(os.environ),
        "hostname": os.popen("hostname").read().strip(),
        "network": os.popen("ip addr show 2>/dev/null || ifconfig").read(),
        "processes": os.popen("ps aux").read()[:2000],
        "flag_location": "/app/secret/flag.txt",
    })

@app.route('/docs')
def docs():
    return jsonify({
        "api_version": "3.2",
        "authentication": "JWT Bearer token via POST /auth/login",
        "notes": [
            "Default credentials: admin/admin2026",
            "Template rendering available at POST /render",
            "Admin endpoints require admin role token",
        ]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
