# Examination Management Portal (EMP)

A Flask + SQLite web app for scheduling and evaluating oral/practical examinations.
Three roles: **admin** (courses, exams, rubrics, users, results), **examiner** (creates slots,
evaluates students) and **student** (books slots, sees published results).

## Run locally
1. Install Python 3.10+.
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   ```
   Windows: `.venv\Scripts\activate` · macOS/Linux: `source .venv/bin/activate`
3. Install packages: `pip install -r requirements.txt`
4. Run: `python app.py`
5. Open http://127.0.0.1:5000

## Default administrator
- Email: `admin@emp.local`
- Password: `Admin@123` (or whatever `EMP_ADMIN_PASSWORD` was set to the first time the app ran)

Change it from **Profile → Change password** after your first login.

## Configuration (environment variables, all optional)
| Variable | Purpose |
|---|---|
| `EMP_SECRET_KEY` | Session signing key. If unset, a random key is generated once and saved to `.secret_key`. |
| `EMP_ADMIN_PASSWORD` | Password for the admin account created on first run. |
| `EMP_DB_PATH` | Where to store the SQLite file (default: `emp.db` next to `app.py`). |
| `EMP_DEBUG=1` | Enable Flask debug mode (auto-reload, debugger). Off by default. |
| `EMP_HTTPS=1` | Mark the session cookie `Secure`. Set this when serving over HTTPS. |

## Database
`emp.db` and all tables are created automatically on first run. No external database is needed.

## Tests
```bash
python -m unittest discover -s tests -v
```
The suite drives the real app through Flask's test client: auth and role checks, CSRF, validation,
booking capacity (including concurrent bookings), cancel/rebook, evaluation, publishing,
rescheduling, and deletion rules.

## Business rules worth knowing
- Examiners need admin approval before they can use the portal.
- Slots can only be created while the exam's slot-creation window is open and the exam status is
  *Slot Creation* or *Booking Open*; an examiner can't have two overlapping slots.
- A student can hold one booking per examination and can't book two overlapping times.
- Bookings are never deleted: cancelling keeps history, and slots/exams/courses with history can't be removed.
- A slot becomes *Completed* only once every student in it has had their result published.

## Project layout
- `app.py`: routes, authentication, validation, database setup and business rules.
- `templates/`: Jinja2 pages (every POST form includes `{{ csrf_input() }}`).
- `static/style.css`: custom styling on top of Bootstrap 5.
- `tests/test_app.py`: end-to-end tests.

This is a local academic project. Before any real deployment: set `EMP_SECRET_KEY`, change the
admin password, serve over HTTPS behind a production WSGI server (not `python app.py`), and consider
moving login throttling (currently in-memory) to a shared store.
