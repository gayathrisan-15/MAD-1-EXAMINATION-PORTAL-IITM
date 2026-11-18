"""End-to-end tests for the Examination Management Portal.

Run from the project folder:  python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import threading
import unittest
from contextlib import closing
from datetime import datetime, timedelta

os.environ["EMP_SECRET_KEY"] = "test-secret"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as emp  # noqa: E402

PW = "Password1!"


def stamp(delta_days):
    return (datetime.now() + timedelta(days=delta_days)).strftime("%Y-%m-%dT%H:%M")


class PortalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        emp.DB_PATH = os.path.join(self.tmp.name, "test.db")
        emp._failed_logins.clear()
        emp.init_db()
        emp.app.config["TESTING"] = True
        self.tomorrow = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")

    def tearDown(self):
        self.tmp.cleanup()

    # -- helpers ----------------------------------------------------------
    def client(self):
        return emp.app.test_client()

    def post(self, c, url, data=None, follow=True):
        with c.session_transaction() as sess:
            sess.setdefault("_csrf", "tok")
            token = sess["_csrf"]
        return c.post(url, data={**(data or {}), "_csrf": token}, follow_redirects=follow)

    def login(self, email, password=PW):
        c = self.client()
        self.post(c, "/login", {"email": email, "password": password})
        return c

    def register(self, name, email, role="student"):
        c = self.client()
        self.post(c, "/register", {"name": name, "email": email, "password": PW, "role": role})

    def user_id(self, email):
        return self.count("SELECT id FROM users WHERE email=?", (email,))

    def admin(self):
        return self.login("admin@emp.local", "Admin@123")

    def seed(self, capacity=1, examiners=1, students=("s1@x.io",)):
        """Course + open exam + approved examiner(s) + slot + students."""
        adm = self.admin()
        self.post(adm, "/courses", {"code": "cs101", "name": "Intro", "status": "Active"})
        self.post(adm, "/exams", {
            "course_id": 1, "name": "Viva 1", "exam_type": "Viva", "duration": 15, "max_marks": 50,
            "slot_start": stamp(-2), "slot_end": stamp(5), "booking_start": stamp(-1),
            "booking_end": stamp(5), "status": "Booking Open"})
        for i in range(examiners):
            email = f"ex{i}@x.io"
            self.register(f"Examiner {i}", email, "examiner")
            self.post(adm, f"/users/{self.user_id(email)}/approve")
        for email in students:
            self.register(email.split("@")[0], email)
        ex = self.login("ex0@x.io")
        self.post(ex, "/slots", {"exam_id": 1, "exam_date": self.tomorrow, "start_time": "10:00",
                                 "end_time": "10:30", "capacity": capacity})
        return adm, ex

    def count(self, sql, params=()):
        """First column of the first row. Closes its connection (Windows can't
        delete a database file that is still open)."""
        with closing(emp.connect()) as conn:
            return conn.execute(sql, params).fetchone()[0]

    # -- security ---------------------------------------------------------
    def test_post_without_csrf_token_is_rejected(self):
        c = self.client()
        c.get("/login")
        r = c.post("/login", data={"email": "admin@emp.local", "password": "Admin@123"})
        self.assertEqual(r.status_code, 400)

    def test_logout_is_post_only(self):
        c = self.admin()
        self.assertEqual(c.get("/logout").status_code, 405)
        self.post(c, "/logout")
        self.assertEqual(c.get("/dashboard").status_code, 302)

    def test_every_post_form_carries_a_token(self):
        adm, _ = self.seed()
        for url in ("/courses", "/exams", "/users", "/slots", "/results", "/profile"):
            html = adm.get(url).get_data(as_text=True)
            for chunk in html.split("<form")[1:]:
                tag = chunk.split(">")[0]
                if 'method="post"' in tag:
                    self.assertIn('name="_csrf"', chunk.split("</form>")[0], url)

    def test_login_throttling(self):
        c = self.client()
        for _ in range(5):
            self.post(c, "/login", {"email": "admin@emp.local", "password": "wrong"})
        r = self.post(c, "/login", {"email": "admin@emp.local", "password": "Admin@123"})
        self.assertEqual(r.status_code, 429)

    def test_deactivated_user_is_locked_out_immediately(self):
        adm, _ = self.seed()
        stu = self.login("s1@x.io")
        self.assertEqual(stu.get("/dashboard").status_code, 200)
        self.post(adm, f"/users/{self.user_id('s1@x.io')}/deactivate")
        self.assertEqual(stu.get("/dashboard").status_code, 302)
        self.assertIn("deactivated", self.post(self.client(), "/login",
                      {"email": "s1@x.io", "password": PW}).get_data(as_text=True))

    def test_pending_examiner_is_gated_until_approved(self):
        adm = self.admin()
        self.register("Pat", "pat@x.io", "examiner")
        pat = self.login("pat@x.io")
        self.assertIn("/pending", pat.get("/slots").headers["Location"])
        self.assertIn("/pending", pat.get("/dashboard").headers["Location"])
        self.post(adm, f"/users/{self.user_id('pat@x.io')}/approve")
        self.assertEqual(pat.get("/slots").status_code, 200)

    def test_role_boundaries(self):
        self.seed()
        stu = self.login("s1@x.io")
        for url in ("/courses", "/exams", "/users", "/results", "/slots", "/bookings"):
            self.assertEqual(stu.get(url).status_code, 403, url)

    def test_change_password(self):
        self.seed()
        stu = self.login("s1@x.io")
        new = {"new_password": "NewPass99", "confirm_password": "NewPass99"}
        self.post(stu, "/profile/password", {"current_password": "wrong", **new})
        self.assertEqual(self.login("s1@x.io", "NewPass99").get("/dashboard").status_code, 302)
        self.post(stu, "/profile/password", {"current_password": PW, **new})
        self.assertEqual(self.login("s1@x.io", "NewPass99").get("/dashboard").status_code, 200)

    # -- validation -------------------------------------------------------
    def test_exam_validation(self):
        adm = self.admin()
        self.post(adm, "/courses", {"code": "c1", "name": "Course", "status": "Active"})
        base = {"course_id": 1, "name": "E", "exam_type": "Viva", "duration": 15, "max_marks": 50,
                "slot_start": stamp(0), "slot_end": stamp(1), "booking_start": stamp(0),
                "booking_end": stamp(1), "status": "Draft"}
        for bad in ({"slot_end": stamp(-1)}, {"duration": "-5"}, {"max_marks": "abc"},
                    {"exam_type": "Hack"}, {"course_id": 99}, {"booking_end": "garbage"}):
            self.post(adm, "/exams", {**base, **bad})
        self.assertEqual(self.count("SELECT COUNT(*) FROM exams"), 0)
        self.post(adm, "/exams", base)
        self.assertEqual(self.count("SELECT COUNT(*) FROM exams"), 1)
        # editing is validated too (the original skipped this)
        self.post(adm, "/exams/1/edit", {**base, "duration": "0"})
        self.assertEqual(self.count("SELECT duration FROM exams"), 15)

    def test_slot_rules(self):
        _, ex = self.seed()
        base = {"exam_id": 1, "exam_date": self.tomorrow, "start_time": "10:15", "end_time": "10:45",
                "capacity": 2}
        self.post(ex, "/slots", base)                                       # overlaps 10:00-10:30
        self.post(ex, "/slots", {**base, "start_time": "11:00", "end_time": "10:00"})  # backwards
        self.post(ex, "/slots", {**base, "exam_date": "2000-01-01", "start_time": "11:00",
                                 "end_time": "11:30"})                        # past
        self.post(ex, "/slots", {**base, "start_time": "11:00", "end_time": "11:30",
                                 "capacity": "0"})
        self.assertEqual(self.count("SELECT COUNT(*) FROM slots"), 1)
        self.post(ex, "/slots", {**base, "start_time": "11:00", "end_time": "11:30"})
        self.assertEqual(self.count("SELECT COUNT(*) FROM slots"), 2)

    def test_marks_validation_rejects_nan_and_out_of_range(self):
        _, ex = self.seed()
        stu = self.login("s1@x.io")
        self.post(stu, "/book/1")
        for bad in ("nan", "inf", "-1", "51", "abc"):
            self.post(ex, "/evaluate/1", {"marks": bad, "remarks": ""})
            self.assertIsNone(self.count("SELECT marks FROM bookings"), bad)
        self.post(ex, "/evaluate/1", {"marks": "42.5", "remarks": "good"})
        self.assertEqual(self.count("SELECT marks FROM bookings"), 42.5)

    # -- booking workflow -------------------------------------------------
    def test_capacity_cancel_and_rebook(self):
        self.seed(capacity=1, students=("s1@x.io", "s2@x.io"))
        s1, s2 = self.login("s1@x.io"), self.login("s2@x.io")
        self.post(s1, "/book/1")
        self.assertEqual(self.count("SELECT status FROM slots"), "Full")
        self.post(s2, "/book/1")
        self.assertEqual(self.count("SELECT COUNT(*) FROM bookings"), 1)
        self.post(s1, "/bookings/1/cancel")
        self.assertEqual(self.count("SELECT status FROM slots"), "Available")
        # Original bug: re-booking the same slot hit the UNIQUE constraint.
        self.post(s1, "/book/1")
        self.assertEqual(self.count("SELECT COUNT(*) FROM bookings"), 1)
        self.assertEqual(self.count("SELECT status FROM bookings"), "Booked")
        self.assertEqual(self.count("SELECT status FROM slots"), "Full")

    def test_one_booking_per_exam(self):
        ex_client = self.seed(capacity=5)[1]
        self.post(ex_client, "/slots", {"exam_id": 1, "exam_date": self.tomorrow,
                                        "start_time": "14:00", "end_time": "14:30", "capacity": 5})
        s1 = self.login("s1@x.io")
        self.post(s1, "/book/1")
        self.post(s1, "/book/2")
        self.assertEqual(self.count("SELECT COUNT(*) FROM bookings"), 1)

    def test_closed_booking_window_blocks_booking(self):
        adm, _ = self.seed()
        base = {"course_id": 1, "name": "Viva 1", "exam_type": "Viva", "duration": 15, "max_marks": 50,
                "slot_start": stamp(-2), "slot_end": stamp(5), "booking_start": stamp(-3),
                "booking_end": stamp(-1), "status": "Booking Open"}
        self.post(adm, "/exams/1/edit", base)
        self.post(self.login("s1@x.io"), "/book/1")
        self.assertEqual(self.count("SELECT COUNT(*) FROM bookings"), 0)

    def test_concurrent_booking_never_overbooks(self):
        students = tuple(f"s{i}@x.io" for i in range(6))
        self.seed(capacity=2, students=students)
        clients = [self.login(e) for e in students]
        barrier = threading.Barrier(len(clients))

        def go(c):
            barrier.wait()
            self.post(c, "/book/1")

        threads = [threading.Thread(target=go, args=(c,)) for c in clients]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(self.count("SELECT COUNT(*) FROM bookings WHERE status='Booked'"), 2)

    # -- evaluation, publishing, rescheduling -----------------------------
    def test_publish_closes_slot_only_when_everyone_is_done(self):
        adm, ex = self.seed(capacity=2, students=("s1@x.io", "s2@x.io"))
        for e in ("s1@x.io", "s2@x.io"):
            self.post(self.login(e), "/book/1")
        self.post(ex, "/evaluate/1", {"marks": "40", "remarks": "ok"})
        self.post(adm, "/results/1/publish")
        self.assertEqual(self.count("SELECT status FROM slots"), "Full")   # s2 still waiting
        self.post(ex, "/evaluate/2", {"marks": "30", "remarks": "ok"})
        self.post(adm, "/results/2/publish")
        self.assertEqual(self.count("SELECT status FROM slots"), "Completed")
        # published result is visible to the student; evaluated booking can't be cancelled
        html = self.login("s1@x.io").get("/dashboard").get_data(as_text=True)
        self.assertIn("40.0 marks", html)

    def test_cannot_cancel_after_evaluation(self):
        _, ex = self.seed()
        s1 = self.login("s1@x.io")
        self.post(s1, "/book/1")
        self.post(ex, "/evaluate/1", {"marks": "10", "remarks": ""})
        self.post(s1, "/bookings/1/cancel")
        self.assertEqual(self.count("SELECT status FROM bookings"), "Booked")

    def test_examiner_cannot_evaluate_someone_elses_booking(self):
        adm, _ = self.seed(examiners=2)
        self.post(self.login("s1@x.io"), "/book/1")
        other = self.login("ex1@x.io")
        self.assertEqual(other.get("/evaluate/1").status_code, 403)
        self.assertEqual(other.get("/evaluate/999").status_code, 404)

    def test_reschedule_frees_the_old_slot(self):
        adm, ex = self.seed(capacity=1)
        self.post(ex, "/slots", {"exam_id": 1, "exam_date": self.tomorrow, "start_time": "15:00",
                                 "end_time": "15:30", "capacity": 1})
        self.post(self.login("s1@x.io"), "/book/1")
        self.assertEqual(self.count("SELECT status FROM slots WHERE id=1"), "Full")
        self.post(adm, "/admin/reschedule/1", {"slot_id": 2})
        self.assertEqual(self.count("SELECT slot_id FROM bookings"), 2)
        self.assertEqual(self.count("SELECT status FROM slots WHERE id=1"), "Available")
        self.assertEqual(self.count("SELECT status FROM slots WHERE id=2"), "Full")

    # -- deletion rules ---------------------------------------------------
    def test_delete_rules_protect_history(self):
        adm, ex = self.seed()
        s1 = self.login("s1@x.io")
        self.post(s1, "/book/1")
        self.post(s1, "/bookings/1/cancel")
        # slot with only a cancelled booking used to crash with a 500
        r = self.post(ex, "/slots/1/delete")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.count("SELECT COUNT(*) FROM slots"), 1)
        self.post(adm, "/exams/1/delete")
        self.assertEqual(self.count("SELECT COUNT(*) FROM exams"), 1)
        # deleting a course used to silently cascade-delete its exams
        self.post(adm, "/courses/1/delete")
        self.assertEqual(self.count("SELECT COUNT(*) FROM courses"), 1)

    def test_search_treats_wildcards_literally(self):
        adm, _ = self.seed()
        html = adm.get("/users?q=%25").get_data(as_text=True)
        self.assertNotIn("s1@x.io", html)

    # -- smoke test -------------------------------------------------------
    def test_every_page_renders_for_every_role(self):
        adm, ex = self.seed()
        stu = self.login("s1@x.io")
        self.post(stu, "/book/1")
        pages = {
            adm: ["/dashboard", "/courses", "/courses/1/edit", "/exams", "/exams/1/edit",
                  "/exams/1/rubrics", "/users", "/slots", "/bookings", "/results",
                  "/admin/reschedule/1", "/profile"],
            ex: ["/dashboard", "/slots", "/bookings", "/evaluate/1", "/profile"],
            stu: ["/dashboard", "/book", "/profile"],
        }
        for client, urls in pages.items():
            for url in urls:
                self.assertEqual(client.get(url).status_code, 200, url)


if __name__ == "__main__":
    unittest.main()
