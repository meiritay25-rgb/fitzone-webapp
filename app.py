#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, json
from datetime import date
from functools import wraps
from flask import (Flask, render_template, request, redirect,
                   url_for, session, jsonify, abort)
import bcrypt

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fitzone-dev-secret-2026")
SYNC_API_KEY = os.environ.get("SYNC_API_KEY", "fz-sync-key-2026")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
DB_PATH      = os.environ.get("DB_PATH", "fitzone.db")
USE_PG       = bool(DATABASE_URL)

DAY_ORDER = {"ראשון":1,"שני":2,"שלישי":3,"רביעי":4,"חמישי":5,"שישי":6,"שבת":7}
DAY_ABBR  = {"א":"ראשון","ב":"שני","ג":"שלישי","ד":"רביעי","ה":"חמישי","ו":"שישי","ש":"שבת"}

print(f"[STARTUP] USE_PG={USE_PG} | DATABASE_URL={'set' if DATABASE_URL else 'EMPTY'}", flush=True)

# ─── DB abstraction ─────────────────────────────────────────
if USE_PG:
    import psycopg
    from psycopg.rows import dict_row

    def get_db():
        return psycopg.connect(DATABASE_URL, row_factory=dict_row)

    def _q(sql):
        return sql.replace("?", "%s")

    def db_one(db, sql, p=()):
        with db.cursor() as c:
            c.execute(_q(sql), p)
            return c.fetchone()

    def db_all(db, sql, p=()):
        with db.cursor() as c:
            c.execute(_q(sql), p)
            return c.fetchall()

    def db_run(db, sql, p=()):
        with db.cursor() as c:
            c.execute(_q(sql), p)

    def init_db():
        db = get_db()
        with db.cursor() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS customers (
                    tz        TEXT PRIMARY KEY,
                    full_name TEXT NOT NULL,
                    email     TEXT UNIQUE NOT NULL,
                    phone     TEXT,
                    branch    TEXT,
                    join_date TEXT
                );
                CREATE TABLE IF NOT EXISTS programs (
                    id           SERIAL PRIMARY KEY,
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
                    created_at    TIMESTAMP DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS checkins (
                    id           SERIAL PRIMARY KEY,
                    tz           TEXT NOT NULL,
                    checkin_date TEXT NOT NULL,
                    program_id   INTEGER,
                    duration_min INTEGER NOT NULL,
                    calories     INTEGER NOT NULL,
                    created_at   TIMESTAMP DEFAULT NOW()
                );
            """)
        db.commit()
        db.close()

    MONTH_SQL = "TO_CHAR(checkin_date::date, 'YYYY-MM')"

else:
    import sqlite3

    def get_db():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def db_one(db, sql, p=()):
        r = db.execute(sql, p).fetchone()
        return dict(r) if r else None

    def db_all(db, sql, p=()):
        return [dict(r) for r in db.execute(sql, p).fetchall()]

    def db_run(db, sql, p=()):
        db.execute(sql, p)

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

    MONTH_SQL = "strftime('%Y-%m', checkin_date)"


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
        acc = db_one(db, "SELECT * FROM accounts WHERE email=?", (email,))
        db.close()
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
            cust = db_one(db, "SELECT 1 FROM customers WHERE LOWER(email)=?", (email,))
            if not cust:
                error = "האימייל לא נמצא במערכת. פנה למועדון לאימות."
            elif db_one(db, "SELECT 1 FROM accounts WHERE email=?", (email,)):
                error = "חשבון כבר קיים לאימייל זה. עבור להתחברות."
            else:
                pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                db_run(db, "INSERT INTO accounts (email,password_hash) VALUES (?,?)",
                       (email, pw_hash))
                db.commit()
                session["email"] = email
                db.close()
                return redirect(url_for("dashboard"))
            db.close()
    return render_template("register.html", error=error)


@app.route("/dashboard")
@login_required
def dashboard():
    email = session["email"]
    db    = get_db()
    cust  = db_one(db, "SELECT * FROM customers WHERE LOWER(email)=?", (email,))
    if not cust:
        db.close()
        session.clear()
        return redirect(url_for("login_page"))

    tz       = cust["tz"]
    programs = db_all(db, "SELECT * FROM programs WHERE tz=?", (tz,))
    for p in programs:
        p["day_of_week"] = DAY_ABBR.get(p["day_of_week"], p["day_of_week"])
    programs = sorted(programs, key=lambda p: DAY_ORDER.get(p["day_of_week"], 99))

    checkins = db_all(db,
        "SELECT c.*, p.program_type, p.day_of_week FROM checkins c "
        "LEFT JOIN programs p ON c.program_id=p.id "
        "WHERE c.tz=? ORDER BY c.checkin_date DESC LIMIT 10", (tz,))

    total_calories = (db_one(db, "SELECT COALESCE(SUM(calories),0) AS s FROM checkins WHERE tz=?", (tz,)) or {}).get("s", 0)
    total_visits   = (db_one(db, "SELECT COUNT(*) AS n FROM checkins WHERE tz=?", (tz,)) or {}).get("n", 0)

    monthly = db_all(db, f"""
        SELECT {MONTH_SQL} AS month,
               COUNT(*)      AS visits,
               SUM(calories) AS calories
        FROM checkins WHERE tz=?
        GROUP BY month ORDER BY month DESC LIMIT 6
    """, (tz,))
    monthly = list(reversed(monthly))
    db.close()

    he_months = ["","ינואר","פברואר","מרץ","אפריל","מאי","יוני",
                 "יולי","אוגוסט","ספטמבר","אוקטובר","נובמבר","דצמבר"]
    month_labels = []
    for m in monthly:
        y, mo = m["month"].split("-")
        month_labels.append(f"{he_months[int(mo)]} {y}")

    return render_template("dashboard.html",
        customer       = cust,
        programs       = programs,
        checkins       = checkins,
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
    cust       = db_one(db, "SELECT tz FROM customers WHERE LOWER(email)=?", (email,))
    program_id = request.form.get("program_id") or None
    duration   = int(request.form.get("duration", 45))
    calories   = 300 if duration >= 90 else 150
    today      = date.today().isoformat()
    db_run(db,
        "INSERT INTO checkins (tz,checkin_date,program_id,duration_min,calories) VALUES (?,?,?,?,?)",
        (cust["tz"], today, program_id, duration, calories))
    db.commit()
    db.close()
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ─── Sync API ────────────────────────────────────────────────
@app.route("/api/sync", methods=["POST"])
def api_sync():
    if request.headers.get("X-Sync-Key", "") != SYNC_API_KEY:
        abort(403)
    data = request.get_json(force=True)
    db   = get_db()

    db_run(db, """
        INSERT INTO customers (tz,full_name,email,phone,branch,join_date)
        VALUES (?,?,?,?,?,?)
        ON CONFLICT(tz) DO UPDATE SET
            full_name=EXCLUDED.full_name, email=EXCLUDED.email,
            phone=EXCLUDED.phone, branch=EXCLUDED.branch, join_date=EXCLUDED.join_date
    """, (data["tz"], data["full_name"], data["email"],
          data.get("phone",""), data.get("branch",""), data.get("join_date","")))

    if data.get("program_type"):
        db_run(db, """
            INSERT INTO programs (tz,program_type,trainer_name,day_of_week,start_time,end_time)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(tz,program_type,day_of_week) DO UPDATE SET
                trainer_name=EXCLUDED.trainer_name,
                start_time=EXCLUDED.start_time, end_time=EXCLUDED.end_time
        """, (data["tz"], data["program_type"], data.get("trainer_name",""),
              data.get("day_of_week",""), data.get("start_time",""), data.get("end_time","")))

    db.commit()
    db.close()
    return jsonify({"ok": True, "tz": data["tz"]})


@app.route("/api/clean-programs", methods=["POST"])
def api_clean_programs():
    if request.headers.get("X-Sync-Key", "") != SYNC_API_KEY:
        abort(403)
    db = get_db()
    db_run(db, "DELETE FROM programs WHERE program_type LIKE '%?%' OR day_of_week LIKE '%?%' OR trainer_name LIKE '%?%'")
    db.commit()
    db.close()
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
