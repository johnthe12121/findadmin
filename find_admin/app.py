from flask import Flask, request, render_template, redirect, url_for, session, abort, make_response, Response
from functools import wraps
from datetime import datetime
import base64
import json

app = Flask(__name__)
app.secret_key = "replace_this_with_a_random_secret_for_ctf"

# Config
REAL_FLAG = "xorion{a9F#2Kp!Qx7@Lm3Z$W8R0T}"
FAKE_FLAG = "RTK{666_rg_gjdjbdu}"
FAK_FLAG = "RTK{_Main_3728_CTF_du}"
ADMIN_USER = "admin_main"
ADMIN_PASS = "password@#123456789@"
REQUIRED_HEADER_NAMES = ("X-Forwarded-For", "X-Forwarded-For")
REQUIRED_HEADER_VALUE = "127.0.0.1"

# In-memory user storage (for demo purposes)
users = {
    "1": {  # Admin user with ID 1 (base64 encoded: "MQ==")
        "id": "1",
        "username": "admin_main",
        "password": "password@#123456789@",
        "email": "ad*in@ever****d.c*m",
        "role": "admin"
    }
}

def header_allowed(req):
    for name in REQUIRED_HEADER_NAMES:
        val = req.headers.get(name)
        if val:
            parts = [p.strip() for p in val.split(",")]
            if REQUIRED_HEADER_VALUE in parts:
                return True
    return False

def require_admin_header_or_404(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not header_allowed(request):
            return abort(404)
        return f(*args, **kwargs)
    return wrapped

@app.errorhandler(404)
def not_found(e):
    body = (
        "<!doctype html>\n"
        "<html>\n"
        "  <head>\n"
        "    <meta charset='utf-8'>\n"
        "    <title>404 Not Found</title>\n"
        "  </head>\n"
        "  <body>\n"
        "    <h1>404 Not Found</h1>\n"
        "    <p>The requested URL was not found on this server.</p>\n"
        "  </body>\n"
        "</html>\n"
    )
    resp = make_response(body, 404)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    return resp

@app.route("/")
def index():
    year = datetime.now().year
    return render_template("index.html", message=None, year=year)

# --- Registration Page ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    email = request.form.get("email", "").strip()

    if not username or not password or not email:
        return render_template("register.html", error="All fields are required"), 400

    # Check if username already exists
    for user_id, user in users.items():
        if user["username"] == username:
            return render_template("register.html", error="Username already exists"), 400

    # Create new user with next available ID
    new_id = str(len(users) + 1)
    users[new_id] = {
        "id": new_id,
        "username": username,
        "password": password,
        "email": email,
        "role": "user"
    }

    return redirect(url_for("login", message="Registration successful! Please login."))

# --- Login Page ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        message = request.args.get("message")
        return render_template("login.html", message=message)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    # Find user
    user = None
    user_id = None
    for uid, u in users.items():
        if u["username"] == username and u["password"] == password:
            user = u
            user_id = uid
            break

    if user:
        session["user_id"] = user_id
        session["username"] = user["username"]
        session["role"] = user["role"]
        return redirect(url_for("profile", profile_id=base64.b64encode(user_id.encode()).decode()))

    return render_template("login.html", error="Invalid credentials"), 401

# --- Logout ---
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# --- Profile Page (IDOR vulnerability here) ---
@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Get profile_id from query parameter (base64 encoded)
    encoded_id = request.args.get("profile_id", "")

    if not encoded_id:
        # Default to current user's profile
        encoded_id = base64.b64encode(session["user_id"].encode()).decode()
        return redirect(url_for("profile", profile_id=encoded_id))

    try:
        # Decode the base64 ID
        profile_id = base64.b64decode(encoded_id.encode()).decode()

        # Check if user exists
        if profile_id not in users:
            return render_template("profile.html",
                                 error="Profile not found",
                                 username=session["username"],
                                 is_own_profile=False)

        user_data = users[profile_id]
        is_own_profile = session["user_id"] == profile_id

        return render_template("profile.html",
                             user_data=user_data,
                             is_own_profile=is_own_profile,
                             encoded_id=encoded_id)

    except:
        return render_template("profile.html",
                             error="Invalid profile ID",
                             username=session["username"],
                             is_own_profile=False)

# --- Real Admin Login (GET + POST) ---
@app.route("/admin", methods=["GET", "POST", "TRACE"], strict_slashes=False)
def admin():
    if request.method == "TRACE":
        headers_text = "TRACE ECHO - request headers:\n"
        for k, v in request.headers.items():
            headers_text += f"{k}: {v}\n"
        headers_text += "X-Forwarded-For: 127.0.0.1\n"
        return Response(headers_text, mimetype="text/plain")

    # Require header
    if not header_allowed(request):
        abort(404)

    if request.method == "GET":
        return render_template("admin_login.html")

    # POST → process login
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username == ADMIN_USER and password == ADMIN_PASS:
        session["admin_authenticated"] = True
        return redirect(url_for("admin_panel"))
    return render_template("admin_login.html", error="Invalid credentials"), 401

# Admin panel
@app.route("/admin/panel")
@require_admin_header_or_404
def admin_panel():
    if not session.get("admin_authenticated"):
        return redirect(url_for("admin"))

    # TRUST CLIENT-SENT ROLE (bug)
    role = request.headers.get("X-Header-Role", "1:user")

    if role == "0:admin":
        return make_response(
            render_template("admin_panel.html", flag=REAL_FLAG),
            200,
            {"X-Header-Role": "0:admin"}
        )

    return make_response(
        render_template("admin_panel.html", flag=FAK_FLAG),
        200,
        {"X-Header-Role": "1:user"}
    )

@app.route("/robots.txt")
def robots_txt():
    content = (
        "User-agent: *\n"
        "Disallow: /admin/login\n"
        "Disallow: /admin\n"
        ""
    )
    return Response(content, mimetype="text/plain")

# Fake login (decoy)
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login_fake():
    if request.method == "GET":
        return render_template("fake_login.html")
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username == ADMIN_USER and password == ADMIN_PASS:
        return render_template("fake_flag.html", fake_flag=FAKE_FLAG)
    return render_template("fake_login.html", error="Invalid credentials"), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
