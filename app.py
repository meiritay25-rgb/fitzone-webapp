#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sqlite3, os, json
from datetime import date
from functools import wraps
from flask import (Flask, render_template, request, redirect,
                   url_for, session, jsonify, abort)
import bcrypt

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fitzone-dev-secret-2026")
SYNC_API_KEY  = os.environ.get("SYNC_API_KEY", "fz-sync-key-2026")
DB_PATH = os.environ.get("DB_PATH", "fitzone.db")

DAY_ORDER = {"ראשון":1,"שני":2,"שלישי":3,"רביעי":4,"חמישי":5,"שישי":6,"שבת":7}


# ─── DB helpers ────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS customers (
                tz        TEXT PRIMARY KEY,
                full_name TEXT NOT NULL,
                email     TEXT UNIQUE NOT NULL,
                phone     TEXT,
                branch    TEXT,
                join_date TEXT
            );
            CREATE TABLE IF NOT EXISTS programs (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                tz           TEXT NOT NULL,
                program_type TEXT,
                trainer_name TEXT,
                day_of_week  TEXT,
                start_time   TEXT,
                end_time     TEXT,
                UNIQUE(tz, program_type, day_of_week)
            );
            CREATE TABLE IF NOT EXISTS accounts (
                email         TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                created_at    TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS checkins (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                tz           TEXT NOT NULL,
                checkin_date TEXT NOT NULL,
                program_id   INTEGER,
                duration_min INTEGER NOT NULL,
                calories     INTEGER NOT NULL,
                created_at   TEXT DEFAULT (datetime('now'))
            );
        """)

init_db()


# ─── Auth decorator ─────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "email" not in session:
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


# ─── Routes ─────────────────────────────────────────────────
@app.route("/")
def index():
    if "email" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login_page"))


@app.route("/login", methods=["GET", "POST"])
def login_page():
    error = None
    if request.method == "POST":
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        db  = get_db()
        acc = db.execute("SELECT * FROM accounts WHERE email=?", (email,)).fetchone()
        if acc and bcrypt.checkpw(password.encode(), acc["password_hash"].encode()):
            session["email"] = email
            return redirect(url_for("dashboard"))
        error = "אימייל או סיסמה שגויים"
    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register_page():
    error = None
    if request.method == "POST":
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if len(password) < 6:
            error = "הסיסמה חייבת להכיל לפחות 6 תווים"
        else:
            db   = get_db()
            cust = db.execute("SELECT 1 FROM customers WHERE LOWER(email)=?", (email,)).fetchone()
            if not cust:
                error = "האימייל לא נמצא במערכת. פנה למועדון לאימות."
            elif db.execute("SELECT 1 FROM accounts WHERE email=?", (email,)).fetchone():
                error = "חשבון כבר קיים לאימייל זה. עבור להתחברות."
            else:
                pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                db.execute("INSERT INTO accounts (email,password_hash) VALUES (?,?)", (email, pw_hash))
                db.commit()
                session["email"] = email
                return redirect(url_for("dashboard"))
    return render_template("register.html", error=error)


@app.route("/dashboard")
@login_required
def dashboard():
    email = session["email"]
    db    = get_db()
    cust  = db.execute("SELECT * FROM customers WHERE LOWER(email)=?", (email,)).fetchone()
    if not cust:
        session.clear()
        return redirect(url_for("login_page"))

    tz       = cust["tz"]
    programs = db.execute("SELECT * FROM programs WHERE tz=?", (tz,)).fetchall()
    programs = sorted([dict(p) for p in programs],
                      key=lambda p: DAY_ORDER.get(p["day_of_week"], 99))

    checkins = db.execute(
        "SELECT c.*, p.program_type, p.day_of_week FROM checkins c "
        "LEFT JOIN programs p ON c.program_id=p.id "
        "WHERE c.tz=? ORDER BY c.checkin_date DESC LIMIT 10", (tz,)
    ).fetchall()

    total_calories = db.execute("SELECT COALESCE(SUM(calories),0) FROM checkins WHERE tz=?", (tz,)).fetchone()[0]
    total_visits   = db.execute("SELECT COUNT(*) FROM checkins WHERE tz=?", (tz,)).fetchone()[0]

    monthly = db.execute("""
        SELECT strftime('%Y-%m', checkin_date) AS month,
               COUNT(*)        AS visits,
               SUM(calories)   AS calories
        FROM checkins WHERE tz=?
        GROUP BY month ORDER BY month DESC LIMIT 6
    """, (tz,)).fetchall()
    monthly = list(reversed([dict(m) for m in monthly]))

    # labels in Hebrew month format
    month_labels = []
    for m in monthly:
        y, mo = m["month"].split("-")
        he_months = ["","ינואר","פברואר","מרץ","אפריל","מאי","יוני",
                     "יולי","אוגוסט","ספטמבר","אוקטובר","נובמבר","דצמבר"]
        month_labels.append(f"{he_months[int(mo)]} {y}")

    return render_template("dashboard.html",
        customer       = dict(cust),
        programs       = programs,
        checkins       = [dict(c) for c in checkins],
        total_calories = total_calories,
        total_visits   = total_visits,
        monthly_labels = json.dumps(month_labels,      ensure_ascii=False),
        monthly_visits = json.dumps([m["visits"]   for m in monthly]),
        monthly_cal    = json.dumps([m["calories"] for m in monthly]),
    )


@app.route("/checkin", methods=["POST"])
@login_required
def checkin():
    email      = session["email"]
    db         = get_db()
    cust       = db.execute("SELECT tz FROM customers WHERE LOWER(email)=?", (email,)).fetchone()
    program_id = request.form.get("program_id") or None
    duration   = int(request.form.get("duration", 45))
    calories   = 300 if duration >= 90 else 150
    today      = date.today().isoformat()
    db.execute(
        "INSERT INTO checkins (tz,checkin_date,program_id,duration_min,calories) VALUES (?,?,?,?,?)",
        (cust["tz"], today, program_id, duration, calories)
    )
    db.commit()
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ─── Sync API (called by FitZone_automation.py) ─────────────
@app.route("/api/sync", methods=["POST"])
def api_sync():
    key = request.headers.get("X-Sync-Key","")
    if key != SYNC_API_KEY:
        abort(403)
    data = request.get_json(force=True)
    db   = get_db()

    db.execute("""
        INSERT INTO customers (tz,full_name,email,phone,branch,join_date)
        VALUES (?,?,?,?,?,?)
        ON CONFLICT(tz) DO UPDATE SET
            full_name=excluded.full_name, email=excluded.email,
            phone=excluded.phone, branch=excluded.branch, join_date=excluded.join_date
    """, (data["tz"], data["full_name"], data["email"],
          data.get("phone",""), data.get("branch",""), data.get("join_date","")))

    if data.get("program_type"):
        db.execute("""
            INSERT INTO programs (tz,program_type,trainer_name,day_of_week,start_time,end_time)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(tz,program_type,day_of_week) DO UPDATE SET
                trainer_name=excluded.trainer_name,
                start_time=excluded.start_time, end_time=excluded.end_time
        """, (data["tz"], data["program_type"], data.get("trainer_name",""),
              data.get("day_of_week",""), data.get("start_time",""), data.get("end_time","")))

    db.commit()
    return jsonify({"ok": True, "tz": data["tz"]})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
