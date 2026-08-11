import csv
import os
import sqlite3
from datetime import datetime,timezone
from functools import wraps

from flask import Flask, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_DIR, "honeypot.db")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

os.makedirs(DB_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            operating_system TEXT NOT NULL,
            browser TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL
        )
        """
    )
    conn.commit()

    user_count = conn.execute(
        "SELECT COUNT(*) FROM users WHERE username = ?",
        ("admin",),
    ).fetchone()[0]
    if user_count == 0:
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("admin123"), datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()

    attack_log_count = conn.execute("SELECT COUNT(*) FROM attack_logs").fetchone()[0]
    if attack_log_count == 0:
        seed_sample_data(conn)

    conn.close()


def seed_sample_data(conn):
    sample_logs = [
        {
            "ip_address": "198.51.100.25",
            "username": "root",
            "password": "toor",
            "created_at": (datetime.utcnow() - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S"),
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
            "operating_system": "Windows",
            "browser": "Chrome",
            "failed_attempts": 4,
        },
        {
            "ip_address": "203.0.113.30",
            "username": "admin",
            "password": "password123",
            "created_at": (datetime.utcnow() - timedelta(hours=5)).strftime("%Y-%m-%d %H:%M:%S"),
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Firefox/126.0 Safari/537.36",
            "operating_system": "Linux",
            "browser": "Firefox",
            "failed_attempts": 3,
        },
        {
            "ip_address": "192.0.2.10",
            "username": "support",
            "password": "support2024",
            "created_at": (datetime.utcnow() - timedelta(days=1, hours=3)).strftime("%Y-%m-%d %H:%M:%S"),
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.4",
            "operating_system": "macOS",
            "browser": "Safari",
            "failed_attempts": 2,
        },
        {
            "ip_address": "198.51.100.25",
            "username": "developer",
            "password": "letmein",
            "created_at": (datetime.utcnow() - timedelta(days=1, hours=8)).strftime("%Y-%m-%d %H:%M:%S"),
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/124.0.0.0",
            "operating_system": "Windows",
            "browser": "Edge",
            "failed_attempts": 5,
        },
        {
            "ip_address": "203.0.113.30",
            "username": "guest",
            "password": "guest",
            "created_at": (datetime.utcnow() - timedelta(days=2, hours=4)).strftime("%Y-%m-%d %H:%M:%S"),
            "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Version/17.4 Mobile/15E148 Safari/604.1",
            "operating_system": "iOS",
            "browser": "Safari",
            "failed_attempts": 1,
        },
        {
            "ip_address": "198.51.100.88",
            "username": "root",
            "password": "qwerty",
            "created_at": (datetime.utcnow() - timedelta(days=2, hours=10)).strftime("%Y-%m-%d %H:%M:%S"),
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36",
            "operating_system": "Linux",
            "browser": "Chrome",
            "failed_attempts": 6,
        },
        {
            "ip_address": "192.0.2.77",
            "username": "admin",
            "password": "123456",
            "created_at": (datetime.utcnow() - timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S"),
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "operating_system": "Windows",
            "browser": "Firefox",
            "failed_attempts": 2,
        },
        {
            "ip_address": "198.51.100.41",
            "username": "oracle",
            "password": "oracle123",
            "created_at": (datetime.utcnow() - timedelta(days=4)).strftime("%Y-%m-%d %H:%M:%S"),
            "user_agent": "Mozilla/5.0 (Android 14; Mobile; rv:126.0) Gecko/126.0 Firefox/126.0",
            "operating_system": "Android",
            "browser": "Firefox",
            "failed_attempts": 4,
        },
        {
            "ip_address": "203.0.113.99",
            "username": "postgres",
            "password": "postgres",
            "created_at": (datetime.utcnow() - timedelta(days=5, hours=2)).strftime("%Y-%m-%d %H:%M:%S"),
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36",
            "operating_system": "Windows",
            "browser": "Chrome",
            "failed_attempts": 3,
        },
        {
            "ip_address": "198.51.100.25",
            "username": "backup",
            "password": "backup123",
            "created_at": (datetime.utcnow() - timedelta(days=6)).strftime("%Y-%m-%d %H:%M:%S"),
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.4",
            "operating_system": "macOS",
            "browser": "Safari",
            "failed_attempts": 1,
        },
    ]

    conn.executemany(
        """
        INSERT INTO attack_logs (
            ip_address, username, password, created_at, user_agent, operating_system, browser, failed_attempts
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                item["ip_address"],
                item["username"],
                item["password"],
                item["created_at"],
                item["user_agent"],
                item["operating_system"],
                item["browser"],
                item["failed_attempts"],
            )
            for item in sample_logs
        ],
    )
    conn.commit()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapped


def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def parse_user_agent(user_agent):
    user_agent = (user_agent or "").lower()
    browser = "Unknown"
    if "edg" in user_agent:
        browser = "Edge"
    elif "chrome" in user_agent:
        browser = "Chrome"
    elif "firefox" in user_agent:
        browser = "Firefox"
    elif "safari" in user_agent:
        browser = "Safari"

    operating_system = "Unknown"
    if "windows" in user_agent:
        operating_system = "Windows"
    elif "macintosh" in user_agent or "mac os" in user_agent:
        operating_system = "macOS"
    elif "linux" in user_agent:
        operating_system = "Linux"
    elif "android" in user_agent:
        operating_system = "Android"
    elif "iphone" in user_agent or "ipad" in user_agent:
        operating_system = "iOS"

    return browser, operating_system


def register_attack(username, password):
    ip_address = get_client_ip()
    browser, operating_system = parse_user_agent(request.headers.get("User-Agent", ""))
    conn = get_db_connection()
    failed_attempts = conn.execute(
        "SELECT COUNT(*) FROM attack_logs WHERE ip_address = ? AND username = ?",
        (ip_address, username),
    ).fetchone()[0] + 1
    conn.execute(
        """
        INSERT INTO attack_logs (
            ip_address, username, password, created_at, user_agent, operating_system, browser, failed_attempts
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ip_address,
            username,
            password,
            datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            request.headers.get("User-Agent", "Unknown"),
            operating_system,
            browser,
            failed_attempts,
        ),
    )
    conn.commit()
    conn.close()



def get_logs(filters=None):
    conn = get_db_connection()
    query = "SELECT * FROM attack_logs WHERE 1=1"
    params = []
    if filters:
        if filters.get("ip"):
            query += " AND ip_address LIKE ?"
            params.append(f"%{filters['ip']}%")
        if filters.get("username"):
            query += " AND username LIKE ?"
            params.append(f"%{filters['username']}%")
        if filters.get("date"):
            query += " AND date(created_at) = ?"
            params.append(filters["date"])
        if filters.get("attack_count"):
            query += " AND failed_attempts >= ?"
            params.append(int(filters["attack_count"]))

    query += " ORDER BY created_at DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return rows


def get_dashboard_context(filters=None):
    logs = get_logs(filters)
    unique_ips = {row["ip_address"] for row in logs}
    top_ips = {}
    for row in logs:
        top_ips[row["ip_address"]] = top_ips.get(row["ip_address"], 0) + 1

    top_ip_rows = [
        {"ip": ip, "count": count}
        for ip, count in sorted(top_ips.items(), key=lambda item: item[1], reverse=True)[:5]
    ]

    username_counts = {}
    for row in logs:
        username_counts[row["username"]] = username_counts.get(row["username"], 0) + 1

    browser_counts = {}
    for row in logs:
        browser_counts[row["browser"]] = browser_counts.get(row["browser"], 0) + 1

    daily_counts = {}
    for row in logs:
        day = row["created_at"][:10]
        daily_counts[day] = daily_counts.get(day, 0) + 1

    timeline_labels = list(daily_counts.keys())
    timeline_counts = [daily_counts[label] for label in timeline_labels]

    return {
        "stats": {
            "total_attempts": len(logs),
            "unique_ips": len(unique_ips),
            "recent_logs": logs[:8],
            "top_ips": top_ip_rows,
            "timeline_labels": timeline_labels,
            "timeline_counts": timeline_counts,
            "username_labels": list(username_counts.keys()),
            "username_counts": list(username_counts.values()),
            "browser_labels": list(browser_counts.keys()),
            "browser_counts": list(browser_counts.values()),
        },
        "filters": filters or {},
        "logs": logs,
    }


@app.route("/")
def landing_page():
    return render_template("landing.html")


@app.route("/honeypot", methods=["GET", "POST"])
def honeypot_login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()

        if not username or not password:
            return render_template("fake_login.html", error="Please enter both username and password."), 400

        register_attack(username, password)
        return render_template(
            "fake_login.html",
            error="Authentication failed. This monitored honeypot recorded your attempt.",
        )

    return render_template("fake_login.html")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()

        if not username or not password:
            return render_template("admin_login.html", error="Please provide both fields."), 400

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        return render_template("admin_login.html", error="Invalid administrator credentials."), 401

    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin/dashboard")
@login_required
def dashboard():
    filters = {
        "ip": request.args.get("ip", "").strip(),
        "username": request.args.get("username", "").strip(),
        "date": request.args.get("date", "").strip(),
        "attack_count": request.args.get("attack_count", "").strip(),
    }
    context = get_dashboard_context(filters)
    return render_template("dashboard.html", **context)


@app.route("/admin/export/csv")
@login_required
def export_csv():
    filters = {
        "ip": request.args.get("ip", "").strip(),
        "username": request.args.get("username", "").strip(),
        "date": request.args.get("date", "").strip(),
        "attack_count": request.args.get("attack_count", "").strip(),
    }
    logs = get_logs(filters)
    csv_path = os.path.join(REPORTS_DIR, "attack_logs.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["id", "ip_address", "username", "password", "created_at", "browser", "operating_system", "failed_attempts"])
        for row in logs:
            writer.writerow([row["id"], row["ip_address"], row["username"], row["password"], row["created_at"], row["browser"], row["operating_system"], row["failed_attempts"]])

    return send_file(csv_path, as_attachment=True, download_name="attack_logs.csv", mimetype="text/csv")


@app.route("/admin/export/pdf")
@login_required
def export_pdf():
    filters = {
        "ip": request.args.get("ip", "").strip(),
        "username": request.args.get("username", "").strip(),
        "date": request.args.get("date", "").strip(),
        "attack_count": request.args.get("attack_count", "").strip(),
    }
    logs = get_logs(filters)
    pdf_path = os.path.join(REPORTS_DIR, "attack_logs.pdf")
    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = [Paragraph("Honeypot Attack Monitoring System Report", styles["Title"]), Spacer(1, 12)]
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", styles["BodyText"]))
    story.append(Spacer(1, 12))

    table_rows = [["IP Address", "Username", "Time", "Browser", "Fails"]]
    for row in logs:
        table_rows.append([row["ip_address"], row["username"], row["created_at"], row["browser"], str(row["failed_attempts"])])

    table = Table(table_rows, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#111827")),
            ]
        )
    )
    story.append(table)
    doc.build(story)
    return send_file(pdf_path, as_attachment=True, download_name="attack_logs.pdf", mimetype="application/pdf")


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
