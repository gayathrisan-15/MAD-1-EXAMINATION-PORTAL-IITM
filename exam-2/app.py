"""Examination Management Portal (EMP).

A small Flask + SQLite application for scheduling and evaluating oral/practical
examinations. Roles: admin, examiner, student.
"""
import hmac
import math
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import date, datetime

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from functools import wraps
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("EMP_DB_PATH", os.path.join(BASE_DIR, "emp.db"))

ADMIN_EMAIL = "admin@emp.local"
DEFAULT_ADMIN_PASSWORD = "Admin@123"

COURSE_STATUSES = ("Active", "Inactive")
EXAM_TYPES = ("Viva", "Practical", "Project Demo", "Assessment")
EXAM_STATUSES = ("Draft", "Slot Creation", "Booking Open", "Closed", "Completed")
# Exams in these states accept new slots and new bookings.
OPEN_EXAM_STATUSES = ("Slot Creation", "Booking Open")

# A booking occupies a seat while it is Booked or Completed (not Cancelled).
SEATS_TAKEN_SQL = ("(SELECT COUNT(*) FROM bookings b WHERE b.slot_id = s.id "
                   "AND b.status IN ('Booked', 'Completed'))")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 300


def load_secret_key():
    """Use EMP_SECRET_KEY if set, otherwise create and reuse a local key file."""
    key = os.environ.get("EMP_SECRET_KEY")
    if key:
        return key
    path = os.path.join(BASE_DIR, ".secret_key")
    try:
        with open(path) as fh:
            return fh.read().strip()
    except FileNotFoundError:
        key = secrets.token_hex(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(key)
        return key


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("EMP_HTTPS") == "1",
)


class FormError(Exception):
    """A problem with user input; the message is safe to show to the user."""


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
def connect():
    # isolation_level=None -> autocommit; explicit transactions via transaction().
    conn = sqlite3.connect(DB_PATH, isolation_level=None, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db():
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def query_one(sql, params=()):
    return get_db().execute(sql, params).fetchone()


def query_all(sql, params=()):
    return get_db().execute(sql, params).fetchall()


def execute(sql, params=()):
    return get_db().execute(sql, params).lastrowid


@contextmanager
def transaction():
    """Run a block atomically. BEGIN IMMEDIATE takes the write lock up front,
    so two requests can't both pass a capacity check and then both insert."""
    conn = get_db()
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','examiner','student')),
  department TEXT DEFAULT '',
  contact TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'approved',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS courses(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'Active'
);
CREATE TABLE IF NOT EXISTS exams(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  exam_type TEXT NOT NULL,
  duration INTEGER NOT NULL DEFAULT 15,
  max_marks INTEGER NOT NULL DEFAULT 100,
  slot_start TEXT NOT NULL,
  slot_end TEXT NOT NULL,
  booking_start TEXT NOT NULL,
  booking_end TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Draft'
);
CREATE TABLE IF NOT EXISTS rubrics(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  exam_id INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
  criterion TEXT NOT NULL,
  max_marks REAL NOT NULL,
  weightage REAL NOT NULL DEFAULT 1,
  description TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS slots(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  exam_id INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
  examiner_id INTEGER NOT NULL REFERENCES users(id),
  exam_date TEXT NOT NULL,
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  capacity INTEGER NOT NULL CHECK(capacity > 0),
  status TEXT NOT NULL DEFAULT 'Available'
);
CREATE TABLE IF NOT EXISTS bookings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL REFERENCES users(id),
  slot_id INTEGER NOT NULL REFERENCES slots(id),
  booked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status TEXT NOT NULL DEFAULT 'Booked',
  marks REAL,
  remarks TEXT DEFAULT '',
  result_published INTEGER NOT NULL DEFAULT 0,
  UNIQUE(student_id, slot_id)
);
CREATE INDEX IF NOT EXISTS idx_exams_course ON exams(course_id);
CREATE INDEX IF NOT EXISTS idx_slots_exam ON slots(exam_id);
CREATE INDEX IF NOT EXISTS idx_slots_examiner ON slots(examiner_id, exam_date);
CREATE INDEX IF NOT EXISTS idx_bookings_slot ON bookings(slot_id, status);
CREATE INDEX IF NOT EXISTS idx_bookings_student ON bookings(student_id, status);
"""


def init_db():
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        if not conn.execute("SELECT 1 FROM users WHERE email = ?", (ADMIN_EMAIL,)).fetchone():
            password = os.environ.get("EMP_ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
            conn.execute(
                "INSERT INTO users(name, email, password_hash, role, status) VALUES(?,?,?,?,?)",
                ("System Administrator", ADMIN_EMAIL, generate_password_hash(password),
                 "admin", "approved"))
            if password == DEFAULT_ADMIN_PASSWORD:
                print(f"[EMP] Admin created with the default password. "
                      f"Sign in as {ADMIN_EMAIL} and change it from your profile page.")
    finally:
        conn.close()


init_db()


# --------------------------------------------------------------------------
# Input parsing / validation
# --------------------------------------------------------------------------
def text_field(form, key, label, max_len=200, required=True):
    value = form.get(key, "").strip()
    if required and not value:
        raise FormError(f"{label} is required.")
    if len(value) > max_len:
        raise FormError(f"{label} must be at most {max_len} characters.")
    return value


def int_field(form, key, label, low, high):
    try:
        value = int(form.get(key, "").strip())
    except ValueError:
        raise FormError(f"{label} must be a whole number.") from None
    if not low <= value <= high:
        raise FormError(f"{label} must be between {low} and {high}.")
    return value


def float_field(form, key, label, low, high):
    try:
        value = float(form.get(key, "").strip())
    except ValueError:
        raise FormError(f"{label} must be a number.") from None
    if not math.isfinite(value) or not low <= value <= high:
        raise FormError(f"{label} must be between {low:g} and {high:g}.")
    return value


def datetime_field(form, key, label):
    try:
        return datetime.fromisoformat(form.get(key, "").strip()).strftime("%Y-%m-%dT%H:%M")
    except ValueError:
        raise FormError(f"{label} is not a valid date and time.") from None


def parse_time(value):
    for fmt in ("%H:%M", "%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).time()
        except ValueError:
            continue
    raise ValueError(f"Invalid time: {value!r}")


def time_field(form, key, label):
    try:
        return parse_time(form.get(key, "").strip()).strftime("%H:%M")
    except ValueError:
        raise FormError(f"{label} is not a valid time.") from None


def choice_field(form, key, label, allowed, default=None):
    value = form.get(key, default)
    if value not in allowed:
        raise FormError(f"Choose a valid {label.lower()}.")
    return value


def like_pattern(text):
    """Escape LIKE wildcards so a search for '50%' matches literally."""
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def slot_start_datetime(slot):
    return datetime.combine(date.fromisoformat(slot["exam_date"]), parse_time(slot["start_time"]))


def parse_exam_form(form):
    """Validate the examination form and return the column values."""
    course_id = int_field(form, "course_id", "Course", 1, 2**31)
    if not query_one("SELECT 1 FROM courses WHERE id = ?", (course_id,)):
        raise FormError("Choose a valid course.")
    data = {
        "course_id": course_id,
        "name": text_field(form, "name", "Examination name"),
        "exam_type": choice_field(form, "exam_type", "Type", EXAM_TYPES),
        "duration": int_field(form, "duration", "Duration", 1, 600),
        "max_marks": int_field(form, "max_marks", "Max marks", 1, 1000),
        "slot_start": datetime_field(form, "slot_start", "Slot creation start"),
        "slot_end": datetime_field(form, "slot_end", "Slot creation end"),
        "booking_start": datetime_field(form, "booking_start", "Booking start"),
        "booking_end": datetime_field(form, "booking_end", "Booking end"),
        "status": choice_field(form, "status", "Status", EXAM_STATUSES, "Draft"),
    }
    if data["slot_start"] >= data["slot_end"]:
        raise FormError("Slot creation must end after it starts.")
    if data["booking_start"] >= data["booking_end"]:
        raise FormError("Booking must end after it starts.")
    return data


# --------------------------------------------------------------------------
# Security: CSRF protection, login throttling
# --------------------------------------------------------------------------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


@app.before_request
def verify_csrf():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        expected = session.get("_csrf")
        sent = request.form.get("_csrf", "") or request.headers.get("X-CSRF-Token", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400)


# In-memory failed-login tracker (fine for a single local process).
_failed_logins = {}
# Hashing a throwaway password keeps login timing similar for unknown emails.
_DUMMY_HASH = generate_password_hash(secrets.token_hex(8))


def _recent_failures(key):
    cutoff = time.monotonic() - LOGIN_WINDOW_SECONDS
    attempts = [t for t in _failed_logins.get(key, []) if t > cutoff]
    if attempts:
        _failed_logins[key] = attempts
    else:
        _failed_logins.pop(key, None)
    return attempts


# --------------------------------------------------------------------------
# Authentication helpers
# --------------------------------------------------------------------------
def current_user():
    """The logged-in user row, loaded once per request."""
    if "current_user" in g:
        return g.current_user
    user = None
    user_id = session.get("user_id")
    if user_id is not None:
        user = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
        if user is None or user["status"] == "deactivated":
            deactivated = user is not None
            session.clear()
            user = None
            if deactivated:
                flash("This account has been deactivated.", "danger")
    g.current_user = user
    return user


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def roles(*allowed):
    """Require a logged-in user with one of the given roles."""
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            user = current_user()
            if user["role"] not in allowed:
                abort(403)
            if user["role"] == "examiner" and user["status"] != "approved":
                flash("Your examiner account is awaiting administrator approval.", "warning")
                return redirect(url_for("pending"))
            return fn(*args, **kwargs)
        return wrapper
    return decorator


@app.context_processor
def inject_template_globals():
    def csrf_input():
        return Markup(f'<input type="hidden" name="_csrf" value="{csrf_token()}">')
    return {"logged_user": current_user(), "csrf_input": csrf_input}


# --------------------------------------------------------------------------
# Slot helpers
# --------------------------------------------------------------------------
def seats_taken(slot_id):
    return query_one("SELECT COUNT(*) n FROM bookings WHERE slot_id = ? "
                     "AND status IN ('Booked', 'Completed')", (slot_id,))["n"]


def refresh_slot_status(slot_id):
    """Keep an open slot's Available/Full flag in step with its bookings."""
    slot = query_one("SELECT capacity, status FROM slots WHERE id = ?", (slot_id,))
    if not slot or slot["status"] not in ("Available", "Full"):
        return
    new_status = "Full" if seats_taken(slot_id) >= slot["capacity"] else "Available"
    if new_status != slot["status"]:
        execute("UPDATE slots SET status = ? WHERE id = ?", (new_status, slot_id))


# --------------------------------------------------------------------------
# Public pages: home, register, login, logout
# --------------------------------------------------------------------------
@app.route("/")
def home():
    return redirect(url_for("dashboard" if current_user() else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            name = text_field(request.form, "name", "Name", 100)
            email = text_field(request.form, "email", "Email", 254).lower()
            department = text_field(request.form, "department", "Department", 100, required=False)
            contact = text_field(request.form, "contact", "Contact", 100, required=False)
            role = choice_field(request.form, "role", "Role", ("student", "examiner"), "student")
            password = request.form.get("password", "")
            if not EMAIL_RE.match(email):
                raise FormError("Enter a valid email address.")
            if len(password) < 8:
                raise FormError("Password must be at least 8 characters.")
            status = "pending" if role == "examiner" else "approved"
            execute("INSERT INTO users(name, email, password_hash, role, department, contact, status) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (name, email, generate_password_hash(password), role, department, contact, status))
        except FormError as exc:
            flash(str(exc), "danger")
        except sqlite3.IntegrityError:
            flash("That email is already registered.", "danger")
        else:
            flash("Registration successful. Examiner accounts require admin approval."
                  if role == "examiner" else "Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        throttle_key = (request.remote_addr, email)
        if len(_recent_failures(throttle_key)) >= LOGIN_MAX_FAILURES:
            flash("Too many failed attempts. Please wait a few minutes and try again.", "danger")
            return render_template("login.html"), 429

        user = query_one("SELECT * FROM users WHERE email = ?", (email,))
        password_ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
        if not user or not password_ok:
            _failed_logins.setdefault(throttle_key, []).append(time.monotonic())
            flash("Invalid email or password.", "danger")
        elif user["status"] == "deactivated":
            flash("This account has been deactivated.", "danger")
        else:
            _failed_logins.pop(throttle_key, None)
            session.clear()  # start a fresh session on login
            session["user_id"] = user["id"]
            if user["role"] == "examiner" and user["status"] != "approved":
                return redirect(url_for("pending"))
            return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/pending")
@login_required
def pending():
    user = current_user()
    if user["role"] != "examiner" or user["status"] == "approved":
        return redirect(url_for("dashboard"))
    return render_template("pending.html")


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    if user["role"] == "examiner" and user["status"] != "approved":
        return redirect(url_for("pending"))

    if user["role"] == "admin":
        def count(sql):
            return query_one(sql)["n"]

        stats = {
            "Courses": count("SELECT COUNT(*) n FROM courses"),
            "Examinations": count("SELECT COUNT(*) n FROM exams"),
            "Examiners": count("SELECT COUNT(*) n FROM users WHERE role = 'examiner'"),
            "Students": count("SELECT COUNT(*) n FROM users WHERE role = 'student'"),
            "Slots": count("SELECT COUNT(*) n FROM slots"),
            "Bookings": count("SELECT COUNT(*) n FROM bookings"),
        }
        return render_template(
            "dashboard.html", stats=stats,
            users=query_all("SELECT * FROM users ORDER BY created_at DESC LIMIT 8"),
            exams=query_all("SELECT e.*, c.name course_name FROM exams e "
                            "JOIN courses c ON c.id = e.course_id ORDER BY e.id DESC LIMIT 8"))

    if user["role"] == "examiner":
        slots = query_all(f"""SELECT s.*, e.name exam_name, {SEATS_TAKEN_SQL} booked
            FROM slots s JOIN exams e ON e.id = s.exam_id
            WHERE s.examiner_id = ? ORDER BY s.exam_date, s.start_time""", (user["id"],))
        assigned = query_all("""SELECT DISTINCT e.*, c.name course_name FROM exams e
            JOIN courses c ON c.id = e.course_id JOIN slots s ON s.exam_id = e.id
            WHERE s.examiner_id = ?""", (user["id"],))
        pending_count = query_one("""SELECT COUNT(*) n FROM bookings b JOIN slots s ON s.id = b.slot_id
            WHERE s.examiner_id = ? AND b.status = 'Booked' AND b.marks IS NULL""",
                                  (user["id"],))["n"]
        return render_template("dashboard.html", slots=slots, assigned=assigned,
                               pending_count=pending_count)

    return render_template(
        "dashboard.html",
        exams=query_all("SELECT e.*, c.name course_name FROM exams e "
                        "JOIN courses c ON c.id = e.course_id WHERE e.status != 'Draft' "
                        "ORDER BY e.id DESC"),
        bookings=query_all("""SELECT b.*, s.exam_date, s.start_time, s.end_time,
            e.name exam_name, u.name examiner_name
            FROM bookings b JOIN slots s ON s.id = b.slot_id JOIN exams e ON e.id = s.exam_id
            JOIN users u ON u.id = s.examiner_id
            WHERE b.student_id = ? ORDER BY s.exam_date DESC, s.start_time DESC""", (user["id"],)))


# --------------------------------------------------------------------------
# Admin: courses
# --------------------------------------------------------------------------
def parse_course_form(form):
    return (text_field(form, "code", "Course code", 30).upper(),
            text_field(form, "name", "Course name", 150),
            text_field(form, "description", "Description", 1000, required=False),
            choice_field(form, "status", "Status", COURSE_STATUSES, "Active"))


@app.route("/courses", methods=["GET", "POST"])
@roles("admin")
def courses():
    if request.method == "POST":
        try:
            execute("INSERT INTO courses(code, name, description, status) VALUES(?,?,?,?)",
                    parse_course_form(request.form))
            flash("Course created.", "success")
        except FormError as exc:
            flash(str(exc), "danger")
        except sqlite3.IntegrityError:
            flash("Course code must be unique.", "danger")
        return redirect(url_for("courses"))
    return render_template("courses.html", courses=query_all("SELECT * FROM courses ORDER BY id DESC"))


@app.route("/courses/<int:cid>/edit", methods=["GET", "POST"])
@roles("admin")
def edit_course(cid):
    course = query_one("SELECT * FROM courses WHERE id = ?", (cid,))
    if not course:
        abort(404)
    if request.method == "POST":
        try:
            execute("UPDATE courses SET code = ?, name = ?, description = ?, status = ? WHERE id = ?",
                    (*parse_course_form(request.form), cid))
            flash("Course updated.", "success")
            return redirect(url_for("courses"))
        except FormError as exc:
            flash(str(exc), "danger")
        except sqlite3.IntegrityError:
            flash("Course code must be unique.", "danger")
    return render_template("courses.html", edit=course,
                           courses=query_all("SELECT * FROM courses ORDER BY id DESC"))


@app.post("/courses/<int:cid>/delete")
@roles("admin")
def delete_course(cid):
    if query_one("SELECT 1 FROM exams WHERE course_id = ? LIMIT 1", (cid,)):
        flash("Cannot delete a course that has examinations. Delete or move them first.", "danger")
    else:
        execute("DELETE FROM courses WHERE id = ?", (cid,))
        flash("Course deleted.", "success")
    return redirect(url_for("courses"))


# --------------------------------------------------------------------------
# Admin: examinations and rubrics
# --------------------------------------------------------------------------
EXAM_LIST_SQL = ("SELECT e.*, c.name course_name FROM exams e "
                 "JOIN courses c ON c.id = e.course_id ORDER BY e.id DESC")
EXAM_COLUMNS = ("course_id", "name", "exam_type", "duration", "max_marks", "slot_start",
                "slot_end", "booking_start", "booking_end", "status")


@app.route("/exams", methods=["GET", "POST"])
@roles("admin")
def exams():
    if request.method == "POST":
        try:
            data = parse_exam_form(request.form)
            execute(f"INSERT INTO exams({', '.join(EXAM_COLUMNS)}) "
                    f"VALUES({', '.join('?' * len(EXAM_COLUMNS))})",
                    [data[col] for col in EXAM_COLUMNS])
            flash("Examination created.", "success")
        except FormError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("exams"))
    return render_template("exams.html", exams=query_all(EXAM_LIST_SQL),
                           courses=query_all("SELECT * FROM courses ORDER BY code"))


@app.route("/exams/<int:eid>/edit", methods=["GET", "POST"])
@roles("admin")
def edit_exam(eid):
    exam = query_one("SELECT * FROM exams WHERE id = ?", (eid,))
    if not exam:
        abort(404)
    if request.method == "POST":
        try:
            data = parse_exam_form(request.form)
            assignments = ", ".join(f"{col} = ?" for col in EXAM_COLUMNS)
            execute(f"UPDATE exams SET {assignments} WHERE id = ?",
                    [*(data[col] for col in EXAM_COLUMNS), eid])
            flash("Examination updated.", "success")
            return redirect(url_for("exams"))
        except FormError as exc:
            flash(str(exc), "danger")
    return render_template("exams.html", exams=query_all(EXAM_LIST_SQL), edit=exam,
                           courses=query_all("SELECT * FROM courses ORDER BY code"))


@app.post("/exams/<int:eid>/delete")
@roles("admin")
def delete_exam(eid):
    if query_one("SELECT 1 FROM bookings b JOIN slots s ON s.id = b.slot_id "
                 "WHERE s.exam_id = ? LIMIT 1", (eid,)):
        flash("Cannot delete an examination that has bookings. Set its status to Closed instead.",
              "danger")
    else:
        execute("DELETE FROM exams WHERE id = ?", (eid,))
        flash("Examination deleted.", "success")
    return redirect(url_for("exams"))


@app.route("/exams/<int:eid>/rubrics", methods=["GET", "POST"])
@roles("admin")
def rubrics(eid):
    exam = query_one("SELECT * FROM exams WHERE id = ?", (eid,))
    if not exam:
        abort(404)
    if request.method == "POST":
        try:
            criterion = text_field(request.form, "criterion", "Criterion", 150)
            max_marks = float_field(request.form, "max_marks", "Maximum marks", 0.1, 1000)
            weightage = float_field(request.form, "weightage", "Weightage", 0, 1000) \
                if request.form.get("weightage", "").strip() else 1.0
            description = text_field(request.form, "description", "Description", 500, required=False)
            execute("INSERT INTO rubrics(exam_id, criterion, max_marks, weightage, description) "
                    "VALUES(?,?,?,?,?)", (eid, criterion, max_marks, weightage, description))
            flash("Rubric criterion added.", "success")
            total = query_one("SELECT SUM(max_marks) t FROM rubrics WHERE exam_id = ?", (eid,))["t"]
            if total > exam["max_marks"]:
                flash(f"Heads up: rubric marks now total {total:g}, above the exam maximum "
                      f"of {exam['max_marks']}.", "warning")
        except FormError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("rubrics", eid=eid))
    return render_template("rubrics.html", exam=exam,
                           rubrics=query_all("SELECT * FROM rubrics WHERE exam_id = ?", (eid,)))


@app.post("/rubrics/<int:rid>/delete")
@roles("admin")
def delete_rubric(rid):
    rubric = query_one("SELECT exam_id FROM rubrics WHERE id = ?", (rid,))
    if not rubric:
        abort(404)
    execute("DELETE FROM rubrics WHERE id = ?", (rid,))
    flash("Rubric deleted.", "success")
    return redirect(url_for("rubrics", eid=rubric["exam_id"]))


# --------------------------------------------------------------------------
# Admin: users
# --------------------------------------------------------------------------
@app.route("/users")
@roles("admin")
def users():
    q = request.args.get("q", "").strip()
    pattern = like_pattern(q)
    rows = query_all("""SELECT * FROM users WHERE role != 'admin' AND
        (name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\' OR CAST(id AS TEXT) LIKE ? ESCAPE '\\')
        ORDER BY role, status, name""", (pattern, pattern, pattern))
    return render_template("users.html", users=rows, q=q)


@app.post("/users/<int:uid>/<action>")
@roles("admin")
def manage_user(uid, action):
    user = query_one("SELECT * FROM users WHERE id = ? AND role != 'admin'", (uid,))
    if not user:
        abort(404)
    if action == "approve" and user["role"] == "examiner":
        execute("UPDATE users SET status = 'approved' WHERE id = ?", (uid,))
        flash("Examiner approved.", "success")
    elif action == "deactivate":
        execute("UPDATE users SET status = 'deactivated' WHERE id = ?", (uid,))
        flash("Account deactivated.", "success")
    elif action == "activate":
        execute("UPDATE users SET status = 'approved' WHERE id = ?", (uid,))
        flash("Account activated.", "success")
    else:
        abort(400)
    return redirect(url_for("users"))


# --------------------------------------------------------------------------
# Slots
# --------------------------------------------------------------------------
@app.route("/slots", methods=["GET", "POST"])
@roles("admin", "examiner")
def slots():
    user = current_user()
    if request.method == "POST":
        if user["role"] != "examiner":
            abort(403)
        try:
            create_slot(user, request.form)
            flash("Slot created.", "success")
        except FormError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("slots"))

    sql = f"""SELECT s.*, e.name exam_name, u.name examiner_name, {SEATS_TAKEN_SQL} booked
        FROM slots s JOIN exams e ON e.id = s.exam_id JOIN users u ON u.id = s.examiner_id"""
    if user["role"] == "admin":
        rows = query_all(sql + " ORDER BY s.exam_date, s.start_time")
    else:
        rows = query_all(sql + " WHERE s.examiner_id = ? ORDER BY s.exam_date, s.start_time",
                         (user["id"],))
    open_exams = query_all(f"SELECT * FROM exams WHERE status IN "
                           f"({', '.join('?' * len(OPEN_EXAM_STATUSES))}) ORDER BY name",
                           OPEN_EXAM_STATUSES)
    return render_template("slots.html", slots=rows, exams=open_exams)


def create_slot(examiner, form):
    exam_id = int_field(form, "exam_id", "Examination", 1, 2**31)
    exam = query_one("SELECT * FROM exams WHERE id = ?", (exam_id,))
    if not exam or exam["status"] not in OPEN_EXAM_STATUSES:
        raise FormError("Choose a valid examination that is open for slots.")
    now = datetime.now()
    if not (datetime.fromisoformat(exam["slot_start"]) <= now <= datetime.fromisoformat(exam["slot_end"])):
        raise FormError("Slot creation is not open for this examination.")

    try:
        exam_date = date.fromisoformat(form.get("exam_date", "").strip()).isoformat()
    except ValueError:
        raise FormError("Enter a valid date.") from None
    start_time = time_field(form, "start_time", "Start time")
    end_time = time_field(form, "end_time", "End time")
    capacity = int_field(form, "capacity", "Capacity", 1, 500)
    if start_time >= end_time:
        raise FormError("The slot must end after it starts.")
    if datetime.combine(date.fromisoformat(exam_date), parse_time(start_time)) <= now:
        raise FormError("The slot must start in the future.")

    with transaction():
        clash = query_one("""SELECT 1 FROM slots WHERE examiner_id = ? AND exam_date = ?
            AND start_time < ? AND end_time > ?""", (examiner["id"], exam_date, end_time, start_time))
        if clash:
            raise FormError("You already have a slot that overlaps this time.")
        execute("INSERT INTO slots(exam_id, examiner_id, exam_date, start_time, end_time, capacity, status) "
                "VALUES(?,?,?,?,?,?,'Available')",
                (exam_id, examiner["id"], exam_date, start_time, end_time, capacity))


@app.post("/slots/<int:sid>/delete")
@roles("admin", "examiner")
def delete_slot(sid):
    user = current_user()
    slot = query_one("SELECT * FROM slots WHERE id = ?", (sid,))
    if not slot:
        abort(404)
    if user["role"] == "examiner" and slot["examiner_id"] != user["id"]:
        abort(403)
    if query_one("SELECT 1 FROM bookings WHERE slot_id = ? LIMIT 1", (sid,)):
        flash("A slot with booking history cannot be removed.", "danger")
    else:
        execute("DELETE FROM slots WHERE id = ?", (sid,))
        flash("Slot removed.", "success")
    return redirect(url_for("slots"))


# --------------------------------------------------------------------------
# Student: browse and book slots
# --------------------------------------------------------------------------
@app.route("/book")
@roles("student")
def book():
    q = request.args.get("q", "").strip()
    rows = query_all(f"""SELECT s.*, e.name exam_name, e.exam_type, e.duration,
        c.name course_name, u.name examiner_name, {SEATS_TAKEN_SQL} booked
        FROM slots s JOIN exams e ON e.id = s.exam_id JOIN courses c ON c.id = e.course_id
        JOIN users u ON u.id = s.examiner_id
        WHERE e.status IN ('Slot Creation', 'Booking Open') AND e.name LIKE ? ESCAPE '\\'
          AND s.status = 'Available'
        ORDER BY s.exam_date, s.start_time""", (like_pattern(q),))
    return render_template("book.html", slots=rows, q=q)


@app.post("/book/<int:sid>")
@roles("student")
def create_booking(sid):
    user = current_user()
    try:
        with transaction():
            slot = query_one("""SELECT s.*, e.status exam_status, e.booking_start, e.booking_end
                FROM slots s JOIN exams e ON e.id = s.exam_id WHERE s.id = ?""", (sid,))
            if not slot:
                abort(404)
            now = datetime.now()
            if slot["exam_status"] not in OPEN_EXAM_STATUSES:
                raise FormError("This examination is not open for booking.")
            if not (datetime.fromisoformat(slot["booking_start"]) <= now
                    <= datetime.fromisoformat(slot["booking_end"])):
                raise FormError("Booking is not open for this examination.")
            if slot["status"] != "Available":
                raise FormError("This slot is not available.")
            if slot_start_datetime(slot) <= now:
                raise FormError("This slot has already started.")
            if query_one("""SELECT 1 FROM bookings b JOIN slots s2 ON s2.id = b.slot_id
                WHERE b.student_id = ? AND s2.exam_id = ? AND b.status IN ('Booked', 'Completed')""",
                         (user["id"], slot["exam_id"])):
                raise FormError("You already have a booking for this examination.")
            if query_one("""SELECT 1 FROM bookings b JOIN slots s2 ON s2.id = b.slot_id
                WHERE b.student_id = ? AND b.status = 'Booked' AND s2.exam_date = ?
                  AND s2.start_time < ? AND s2.end_time > ?""",
                         (user["id"], slot["exam_date"], slot["end_time"], slot["start_time"])):
                raise FormError("You already have another booking at that time.")
            if seats_taken(sid) >= slot["capacity"]:
                raise FormError("This slot is full.")

            previous = query_one("SELECT id FROM bookings WHERE student_id = ? AND slot_id = ?",
                                 (user["id"], sid))
            if previous:  # re-booking a slot the student cancelled earlier
                execute("""UPDATE bookings SET status = 'Booked', marks = NULL, remarks = '',
                    result_published = 0, booked_at = CURRENT_TIMESTAMP WHERE id = ?""",
                        (previous["id"],))
            else:
                execute("INSERT INTO bookings(student_id, slot_id) VALUES(?, ?)", (user["id"], sid))
            refresh_slot_status(sid)
        flash("Examination slot booked successfully.", "success")
    except FormError as exc:
        flash(str(exc), "danger")
    except sqlite3.IntegrityError:
        flash("Booking could not be created. Please try again.", "danger")
    return redirect(url_for("book"))


@app.post("/bookings/<int:bid>/cancel")
@roles("student")
def cancel_booking(bid):
    user = current_user()
    with transaction():
        booking = query_one("""SELECT b.*, e.booking_end FROM bookings b
            JOIN slots s ON s.id = b.slot_id JOIN exams e ON e.id = s.exam_id
            WHERE b.id = ? AND b.student_id = ?""", (bid, user["id"]))
        if not booking:
            abort(404)
        if booking["status"] != "Booked":
            flash("Only active bookings can be cancelled.", "danger")
        elif booking["marks"] is not None:
            flash("An evaluated booking cannot be cancelled.", "danger")
        elif datetime.now() > datetime.fromisoformat(booking["booking_end"]):
            flash("Cancellation deadline has passed.", "danger")
        else:
            execute("UPDATE bookings SET status = 'Cancelled' WHERE id = ?", (bid,))
            refresh_slot_status(booking["slot_id"])
            flash("Booking cancelled. History has been retained.", "success")
    return redirect(url_for("dashboard"))


# --------------------------------------------------------------------------
# Admin / examiner: bookings, evaluation, results, rescheduling
# --------------------------------------------------------------------------
@app.route("/bookings")
@roles("admin", "examiner")
def bookings():
    user = current_user()
    q = request.args.get("q", "").strip()
    pattern = like_pattern(q)
    sql = """SELECT b.*, st.name student_name, st.email student_email, s.exam_date,
        s.start_time, s.end_time, e.name exam_name, ex.name examiner_name
        FROM bookings b JOIN users st ON st.id = b.student_id JOIN slots s ON s.id = b.slot_id
        JOIN exams e ON e.id = s.exam_id JOIN users ex ON ex.id = s.examiner_id
        WHERE (st.name LIKE ? ESCAPE '\\' OR st.email LIKE ? ESCAPE '\\'
               OR e.name LIKE ? ESCAPE '\\' OR CAST(b.id AS TEXT) LIKE ? ESCAPE '\\')"""
    params = [pattern] * 4
    if user["role"] == "examiner":
        sql += " AND s.examiner_id = ?"
        params.append(user["id"])
    rows = query_all(sql + " ORDER BY s.exam_date DESC, s.start_time DESC", params)
    return render_template("bookings.html", bookings=rows, q=q)


@app.route("/evaluate/<int:bid>", methods=["GET", "POST"])
@roles("examiner")
def evaluate(bid):
    user = current_user()
    booking = query_one("""SELECT b.*, st.name student_name, s.examiner_id, e.id exam_id,
        e.name exam_name, e.max_marks
        FROM bookings b JOIN users st ON st.id = b.student_id JOIN slots s ON s.id = b.slot_id
        JOIN exams e ON e.id = s.exam_id WHERE b.id = ?""", (bid,))
    if not booking:
        abort(404)
    if booking["examiner_id"] != user["id"] or booking["status"] != "Booked":
        abort(403)
    criteria = query_all("SELECT * FROM rubrics WHERE exam_id = ?", (booking["exam_id"],))
    if request.method == "POST":
        try:
            marks = float_field(request.form, "marks", "Marks", 0, booking["max_marks"])
            remarks = text_field(request.form, "remarks", "Remarks", 2000, required=False)
            execute("UPDATE bookings SET marks = ?, remarks = ? WHERE id = ?", (marks, remarks, bid))
            flash("Evaluation saved. Admin can review it; result is not yet published.", "success")
            return redirect(url_for("bookings"))
        except FormError as exc:
            flash(str(exc), "danger")
    return render_template("evaluate.html", booking=booking, criteria=criteria)


@app.route("/results")
@roles("admin")
def results():
    return render_template("results.html", bookings=query_all("""SELECT b.*, st.name student_name,
        e.name exam_name, s.exam_date FROM bookings b JOIN users st ON st.id = b.student_id
        JOIN slots s ON s.id = b.slot_id JOIN exams e ON e.id = s.exam_id
        WHERE b.marks IS NOT NULL AND b.status != 'Cancelled'
        ORDER BY s.exam_date DESC, b.id DESC"""))


@app.post("/results/<int:bid>/publish")
@roles("admin")
def publish_result(bid):
    with transaction():
        booking = query_one("SELECT * FROM bookings WHERE id = ? AND marks IS NOT NULL "
                            "AND status IN ('Booked', 'Completed')", (bid,))
        if not booking:
            abort(404)
        execute("UPDATE bookings SET result_published = 1, status = 'Completed' WHERE id = ?", (bid,))
        # Only close the slot once nobody in it is still waiting for a result.
        waiting = query_one("SELECT 1 FROM bookings WHERE slot_id = ? AND status = 'Booked'",
                            (booking["slot_id"],))
        if not waiting:
            execute("UPDATE slots SET status = 'Completed' WHERE id = ?", (booking["slot_id"],))
    flash("Result published to the student.", "success")
    return redirect(url_for("results"))


@app.route("/admin/reschedule/<int:bid>", methods=["GET", "POST"])
@roles("admin")
def reschedule(bid):
    booking = query_one("""SELECT b.*, st.name student_name, s.exam_id, e.name exam_name
        FROM bookings b JOIN users st ON st.id = b.student_id JOIN slots s ON s.id = b.slot_id
        JOIN exams e ON e.id = s.exam_id WHERE b.id = ?""", (bid,))
    if not booking:
        abort(404)
    if booking["status"] != "Booked" or booking["marks"] is not None:
        flash("Only active, not-yet-evaluated bookings can be rescheduled.", "danger")
        return redirect(url_for("bookings"))

    if request.method == "POST":
        try:
            new_slot_id = int_field(request.form, "slot_id", "Slot", 1, 2**31)
            with transaction():
                new_slot = query_one("SELECT * FROM slots WHERE id = ? AND exam_id = ? "
                                     "AND status = 'Available' AND id != ?",
                                     (new_slot_id, booking["exam_id"], booking["slot_id"]))
                if not new_slot:
                    raise FormError("Choose a different available slot for the same examination.")
                if seats_taken(new_slot_id) >= new_slot["capacity"]:
                    raise FormError("Selected slot is full.")
                if query_one("SELECT 1 FROM bookings WHERE student_id = ? AND slot_id = ?",
                             (booking["student_id"], new_slot_id)):
                    raise FormError("The student already has a booking record in that slot.")
                execute("UPDATE bookings SET slot_id = ? WHERE id = ?", (new_slot_id, bid))
                refresh_slot_status(booking["slot_id"])   # old slot may have a free seat now
                refresh_slot_status(new_slot_id)
            flash("Booking rescheduled.", "success")
            return redirect(url_for("bookings"))
        except FormError as exc:
            flash(str(exc), "danger")

    choices = query_all("""SELECT s.*, u.name examiner_name FROM slots s
        JOIN users u ON u.id = s.examiner_id
        WHERE s.exam_id = ? AND s.status = 'Available' AND s.id != ?
        ORDER BY s.exam_date, s.start_time""", (booking["exam_id"], booking["slot_id"]))
    return render_template("reschedule.html", booking=booking, choices=choices)


# --------------------------------------------------------------------------
# Profile
# --------------------------------------------------------------------------
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    if request.method == "POST":
        try:
            execute("UPDATE users SET name = ?, department = ?, contact = ? WHERE id = ?",
                    (text_field(request.form, "name", "Name", 100),
                     text_field(request.form, "department", "Department", 100, required=False),
                     text_field(request.form, "contact", "Contact", 100, required=False),
                     user["id"]))
            flash("Profile updated.", "success")
        except FormError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("profile"))
    return render_template("profile.html", user=user)


@app.post("/profile/password")
@login_required
def change_password():
    user = current_user()
    current = request.form.get("current_password", "")
    new = request.form.get("new_password", "")
    if not check_password_hash(user["password_hash"], current):
        flash("Your current password is incorrect.", "danger")
    elif len(new) < 8:
        flash("The new password must be at least 8 characters.", "danger")
    elif new != request.form.get("confirm_password", ""):
        flash("The new passwords do not match.", "danger")
    else:
        execute("UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new), user["id"]))
        flash("Password changed.", "success")
    return redirect(url_for("profile"))


# --------------------------------------------------------------------------
# Error pages
# --------------------------------------------------------------------------
def error_page(code, message):
    return render_template("error.html", code=code, message=message), code


@app.errorhandler(400)
def bad_request(_e):
    return error_page(400, "That request could not be processed. If a form expired, "
                           "go back, refresh the page and try again.")


@app.errorhandler(403)
def forbidden(_e):
    return error_page(403, "You do not have permission to access this page.")


@app.errorhandler(404)
def not_found(_e):
    return error_page(404, "The requested record or page was not found.")


@app.errorhandler(405)
def method_not_allowed(_e):
    return error_page(405, "That action is not allowed on this page.")


@app.errorhandler(500)
def server_error(_e):
    return error_page(500, "Something went wrong on our side. Please try again.")


if __name__ == "__main__":
    app.run(debug=os.environ.get("EMP_DEBUG") == "1")
