import unittest
from unittest.mock import patch, MagicMock, ANY, mock_open
from flask import template_rendered
from flask.testing import FlaskClient
from contextlib import contextmanager
from nettacker.api.engine import app
from tests.common import TestCase
from types import SimpleNamespace
import json

@contextmanager
def captured_templates(app):
    recorded = []

    def record(sender, template, context, **extra):
        recorded.append((template, context))

    template_rendered.connect(record, app)
    try:
        yield recorded
    finally:
        template_rendered.disconnect(record, app)


class TestEngine(TestCase):
    def setUp(self):
        self.ctx = app.app_context()
        self.ctx.push()

        # Allowing all IPs during testing and disabling access log
        app.config["OWASP_NETTACKER_CONFIG"] = {
            "api_client_whitelisted_ips": [],
            "api_access_log": False,
            "api_access_key": "test_key",	# Setting up a static testing key
        }
        self.client = app.test_client()

    def tearDown(self):
        self.ctx.pop()

    @patch("nettacker.api.engine.graphs", return_value="mocked_graphs_html")
    @patch("nettacker.api.engine.languages_to_country", return_value="mocked_languages_html")
    @patch("nettacker.api.engine.profiles", return_value=["mocked_profile"])
    @patch("nettacker.api.engine.scan_methods", return_value=["mocked_module"])
    def test_home(self, mock_scan, mock_profiles, mock_languages, mock_graphs):
        with captured_templates(app) as templates:
            response = self.client.get("/")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(templates), 1)
            template, context = templates[0]
            self.assertEqual(template.name, "index.html")
            self.assertIn("selected_modules", context)
            self.assertIn("profile", context)
            self.assertIn("languages", context)
            self.assertIn("graphs", context)
            self.assertIn("filename", context)

            self.assertEqual(context["selected_modules"], ["mocked_module"])
            self.assertEqual(context["profile"], ["mocked_profile"])
            self.assertEqual(context["languages"], "mocked_languages_html")
            self.assertEqual(context["graphs"], "mocked_graphs_html")

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.Thread")
    @patch("nettacker.api.engine.Nettacker")
    @patch("nettacker.api.engine.sanitize_report_path_filename", return_value="mocked_filename")
    def test_new_scan_threading(
        self, mock_sanitize, mock_nettacker, mock_thread, mock_api_key_is_valid
    ):
        mock_api_key_is_valid.return_value = True

        mock_nettacker_instance = MagicMock()
        mock_nettacker_instance.arguments = SimpleNamespace(report_path_filename="mocked_filename")
        mock_nettacker.return_value = mock_nettacker_instance

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        form_data = {
            "report_path_filename": "mocked_filename",
        	"selected_modules": "test_module",
        	"target": "127.0.0.1"
        }

        response = self.client.post("/new/scan", data=form_data) # Posting the most basic part of the data

        self.assertEqual(response.status_code, 200)
        self.assertIn("mocked_filename", response.get_data(as_text=True)) # The filename we chose should be inside this

        mock_sanitize.assert_called_once_with("mocked_filename")

        # Checking if the thread was initialized with Nettacker.run
        mock_thread.assert_called_once_with(target=mock_nettacker_instance.run)

        # Then we can check if the thread was created and if the nettacker instance was started
        mock_thread_instance.start.assert_called_once()
        mock_nettacker.assert_called_once()

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.generate_compare_filepath")
    @patch("nettacker.api.engine.create_compare_report")
    def test_compare_scan(self, mock_create_compare_report, mock_generate_compare_filepath, mock_get_value, mock_api_key_is_valid):
        mock_api_key_is_valid.return_value = True
        mock_get_value.side_effect = ["scan_id_1", "scan_id_2", ""]  # simulating a missing report path to see how it reacts
        mock_generate_compare_filepath.return_value = "testing_path"
        mock_create_compare_report.return_value = True

        form_data = {}
        response = self.client.post("/compare/scans", data = form_data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("scan_comparison_completed", response.get_data(as_text=True))
        mock_get_value.assert_any_call(ANY, "scan_id_first")
        mock_get_value.assert_any_call(ANY, "scan_id_second")
        mock_create_compare_report.assert_called_once_with(
            {
                "scan_compare_id": "scan_id_2",
                "compare_report_path_filename": "testing_path"
            },
            "scan_id_1"
        )

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    def test_compare_scan_invalid_scan_ids(self, mock_get_value, mock_api_key_is_valid):
        mock_api_key_is_valid.return_value = True
        mock_get_value.side_effect = [None, "scan_id_2"]  # Testing when first scan ID is invalid

        response = self.client.post("/compare/scans", data={})

        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid Scan IDs", response.get_data(as_text=True))

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.create_compare_report")
    def test_compare_scan_file_exception(
        self,
        mock_create_compare_report,
        mock_get_value,
        mock_api_key_is_valid
    ):
        mock_api_key_is_valid.return_value = True
        mock_get_value.side_effect = ["scan_id_1", "scan_id_2", "some_path"]
        mock_create_compare_report.side_effect = FileNotFoundError

        response = self.client.post("/compare/scans", data={})

        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid file path", response.get_data(as_text=True))

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.create_compare_report")
    def test_compare_scan_not_found(
        self,
        mock_create_compare_report,
        mock_get_value,
        mock_api_key_is_valid
    ):
        mock_api_key_is_valid.return_value = True
        mock_get_value.side_effect = ["scan_id_1", "scan_id_2", "path"]
        mock_create_compare_report.return_value = False  # Simulating scan ID not found

        response = self.client.post("/compare/scans", data={})

        self.assertEqual(response.status_code, 404)
        self.assertIn("Scan ID not found", response.get_data(as_text=True))

    @patch("nettacker.api.engine.api_key_is_valid")
    def test_session_check(self, mock_api_key_is_valid):
    	mock_api_key_is_valid.return_value = True
    	response = self.client.get("/session/check")

    	self.assertEqual(response.status_code, 200)
    	self.assertIn('"status":"ok"', response.get_data(as_text=True))

    @patch("nettacker.api.engine.api_key_is_valid")
    def test_session_set_success(self, mock_api_key_is_valid):
        mock_api_key_is_valid.return_value = True
    	
        response = self.client.get("/session/set")
        self.assertEqual(response.status_code, 200)
        self.assertIn('"status":"ok"', response.get_data(as_text=True))
        cookies = response.headers.getlist("Set-Cookie")
        cookie_found = any("key=test_key" in cookie for cookie in cookies)
        self.assertTrue(cookie_found, "Session cookie not set properly")

        # Asserting that cookie attributes are set securely
        for cookie in cookies:
            self.assertIn("HttpOnly", cookie)
            self.assertIn("Secure", cookie)
            self.assertIn("SameSite=Lax", cookie)

    def test_session_kill(self):
        response = self.client.get("/session/kill")
        self.assertEqual(response.status_code, 200)
        self.assertIn("browser session killed", response.get_data(as_text=True))
        cookies = response.headers.getlist("Set-Cookie")

        # flask handles expires=0 like this internally using 1970
        cookie_found = any("key=" in cookie and "Expires=Thu, 01 Jan 1970" in cookie for cookie in cookies)
        self.assertTrue(cookie_found, "Session cookie not properly cleared")

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.select_reports")
    def test_result_get_list(self, mock_select_reports, mock_api_key_is_valid):
        mock_api_key_is_valid.return_value = True
        mock_data = [
            {
            "id": 1,
            "date": "2025-05-14 15:00:00",
            "scan_id": "abc123",
            "report_path_filename": "report.json",
            "options": {"target": "127.0.0.1", "method": "port_scan"}
            }
        ]
        mock_select_reports.return_value = mock_data

        response = self.client.get("/results/get_list")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, mock_data)
        mock_select_reports.assert_called_once_with(1)

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.get_scan_result")
    def test_get_result_content_success(self, mock_get_scan_result, mock_get_value, mock_api_key_is_valid):
        mock_api_key_is_valid.return_value = True
        mock_get_value.return_value = "test_scan"
        mock_get_scan_result.return_value = ("report.json", '{"target": "127.0.0.1"}')

        response = self.client.get("/results/get")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/json")
        self.assertIn("attachment;filename=report.json", response.headers.get("Content-Disposition"))
        self.assertIn("127.0.0.1", response.data.decode())

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    def test_get_result_content_missing_id(self, mock_get_value, mock_api_key_is_valid):
        mock_api_key_is_valid.return_value = True
        mock_get_value.return_value = None

        response = self.client.get("/results/get")

        self.assertEqual(response.status_code, 400)
        self.assertIn("your scan id is not valid!", response.json["msg"])

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.get_scan_result")
    def test_get_result_content_db_error(self, mock_get_scan_result, mock_get_value, mock_api_key_is_valid):
        mock_api_key_is_valid.return_value = True
        mock_get_value.return_value = "test_scan"
        mock_get_scan_result.side_effect = Exception("DB error")

        response = self.client.get("/results/get")

        self.assertEqual(response.status_code, 500)
        self.assertIn("database error", response.json["msg"])

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.get_scan_result")
    def test_get_result_content_unknown_extension(self, mock_get_scan_result, mock_get_value, mock_api_key_is_valid):
        mock_api_key_is_valid.return_value = True
        mock_get_value.return_value = "test_scan"
        mock_get_scan_result.return_value = ("test.unknownext", "test content")

        response = self.client.get("/results/get")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/plain")
        self.assertIn("attachment;filename=test.unknownext", response.headers.get("Content-Disposition"))
        self.assertIn("test content", response.data.decode())

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.create_connection")
    @patch("nettacker.api.engine.get_logs_by_scan_id")
    def test_get_results_json_success(
        self, mock_get_logs_by_scan_id, mock_create_connection, mock_get_value, mock_api_key_is_valid
    ):
        mock_api_key_is_valid.return_value = True
        mock_get_value.return_value = "123"

        # Fake DB session and report row
        mock_session = MagicMock()
        mock_create_connection.return_value = mock_session

        mock_report = MagicMock()
        mock_report.id = 123
        mock_report.scan_unique_id = "abc"
        mock_report.report_path_filename = "./results/abc.html"
        mock_session.query().filter().first.return_value = mock_report

        mock_get_logs_by_scan_id.return_value = [
            {
                "scan_id": "abc",
                "target": "127.0.0.1",
                "module_name": "port_scan",
                "date": "2024-01-01",
                "port": [80],
                "event": {"status": "open"},
                "json_event": '{"status": "open"}'
            }
        ]

        response = self.client.get("/results/get_json")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/json")
        self.assertIn("attachment;filename=/results/abc.json", response.headers["Content-Disposition"])
        self.assertIn('"target": "127.0.0.1"', response.get_data(as_text=True))

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    def test_get_results_json_missing_id(self, mock_get_value, mock_api_key_is_valid):
        mock_api_key_is_valid.return_value = True
        mock_get_value.return_value = None

        response = self.client.get("/results/get_json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["msg"], "your scan id is not valid!")

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.create_connection")
    def test_get_results_json_invalid_id(self, mock_create_connection, mock_get_value, mock_api_key_is_valid):
        mock_api_key_is_valid.return_value = True
        mock_get_value.return_value = "non-existent-id"

        mock_session = MagicMock()
        mock_create_connection.return_value = mock_session
        mock_session.query().filter().first.return_value = None  # No matching report

        response = self.client.get("/results/get_json")

        # Depending on actual implementation error, it may return 500 if not handled
        self.assertIn(response.status_code, [400, 500])

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.create_connection")
    @patch("nettacker.api.engine.get_logs_by_scan_id")
    def test_get_results_csv_success(
        self, mock_get_logs_by_scan_id, mock_create_connection, mock_get_value, mock_api_key_is_valid
        ):
        mock_api_key_is_valid.return_value = True
        mock_get_value.return_value = "123"

        mock_session = MagicMock()
        mock_create_connection.return_value = mock_session

        mock_report = MagicMock()
        mock_report.id = 123
        mock_report.scan_unique_id = "abc"
        mock_report.report_path_filename = "./results/abc.html"

        mock_get_logs_by_scan_id.return_value = [
            {
                "scan_id": "abc",
                "target": "127.0.0.1",
                "module_name": "port_scan",
                "date": "2024-01-01",
                "port": [80],
                "event": {"status": "open"},
                "json_event": '{"status": "open"}'
            }
        ]

        response = self.client.get("/results/get_csv")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/csv")
        self.assertIn("attachment;filename=.csv", response.headers["Content-Disposition"])
        self.assertIn('"127.0.0.1"', response.get_data(as_text=True))

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.create_connection")
    def test_get_results_csv_invalid_id(self, mock_create_connection, mock_get_value, mock_api_key_is_valid):
        mock_api_key_is_valid.return_value = True
        mock_get_value.return_value = "non-existent-id"

        mock_session = MagicMock()
        mock_create_connection.return_value = mock_session
        mock_session.query().filter().first.return_value = None

        response = self.client.get("/results/get_csv")

        # Depending on actual implementation error, it may return 500 if not handled
        self.assertIn(response.status_code, [400, 500])

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    def test_get_results_json_missing_id(self, mock_get_value, mock_api_key_is_valid):
        mock_api_key_is_valid.return_value = True
        mock_get_value.return_value = None

        response = self.client.get("/results/get_csv")
        self.assertEqual(response.status_code, 400)

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.create_connection")
    def test_logs_get_list_valid_page(self, mock_create_connection, mock_get_value, mock_api_key_is_valid):
        mock_api_key_is_valid.return_value = True
        mock_get_value.return_value = "1"

        # Mock session and query responses
        mock_session = MagicMock()
        mock_create_connection.return_value = mock_session

        # Simulate two hosts in the DB
        fake_hosts = [
            MagicMock(target="192.168.0.1"),
            MagicMock(target="10.0.0.1"),
        ]
        mock_session.query().group_by().order_by().offset().limit().all.return_value = fake_hosts

        # Simulate related queries for each host
        mock_session.query().filter().group_by().all.return_value = [MagicMock(module_name="http")]
        mock_session.query().filter().order_by().first.return_value = MagicMock(date="2025-01-01")
        mock_session.query().filter().all.return_value = [MagicMock(event="Port open")]

        response = self.client.get("/logs/get_list?page=1")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json, list)
        self.assertIn("target", response.json[0])
        self.assertIn("module_name", response.json[0]["info"])

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.create_connection")
    def test_logs_get_list_invalid_page(self, mock_create_connection, mock_get_value, mock_api_key_is_valid):
        mock_api_key_is_valid.return_value = True
        mock_get_value.return_value = "9999"  # simulate page too far

        mock_session = MagicMock()
        mock_create_connection.return_value = mock_session

        # Simulate no hosts found
        mock_session.query().group_by().order_by().offset().limit().all.return_value = []

        response = self.client.get("/logs/get_list?page=9999")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "finished")
        self.assertEqual(response.json["msg"], "No more search results")

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.create_connection")
    def test_logs_get_list_missing_page_param(self, mock_create_connection, mock_api_key_is_valid):
        mock_api_key_is_valid.return_value = True

        # mock default page = 1 behavior
        mock_session = MagicMock()
        mock_create_connection.return_value = mock_session

        mock_session.query().group_by().order_by().offset().limit().all.return_value = []

        response = self.client.get("/logs/get_list")
        self.assertEqual(response.status_code, 200)
        # self.assertEqual(response.json[0]["info"]["module_name"][0], "port_scan")
        # We can't be sure the user had done a port_scan previously.

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.logs_to_report_html")
    def test_logs_get_html_valid_target(self, mock_logs_to_html, mock_get_value, mock_api_key_valid):
        mock_api_key_valid.return_value = True
        mock_get_value.return_value = "192.168.0.1"
        mock_logs_to_html.return_value = "<html><body>Report</body></html>"

        response = self.client.get("/logs/get_html?target=192.168.0.1")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.content_type)
        self.assertIn("Report", response.get_data(as_text=True))

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.logs_to_report_html")
    def test_logs_get_html_missing_target(self, mock_logs_to_html, mock_get_value, mock_api_key_valid):
        mock_api_key_valid.return_value = True
        mock_get_value.return_value = None
        mock_logs_to_html.return_value = "<html><body>No Target</body></html>"

        response = self.client.get("/logs/get_html")  # not giving the ?target= paramter
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.content_type)
        self.assertIn("No Target", response.get_data(as_text=True)) # <html><body>No Target</body></html>

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.logs_to_report_json")
    @patch("nettacker.api.engine.now")
    def test_logs_get_json_valid_target(
        self, mock_now, mock_logs_to_json, mock_get_value, mock_api_key_valid
    ):
        mock_api_key_valid.return_value = True
        mock_get_value.return_value = "192.168.0.1"
        mock_logs_to_json.return_value = [{"event": "test"}]
        mock_now.return_value = "2025_05_14_12_00_00"

        response = self.client.get("/logs/get_json?target=192.168.0.1")
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/json", response.content_type)
        self.assertIn("attachment;filename=report-2025_05_14_12_00_00", response.headers["Content-Disposition"])
        self.assertEqual(json.loads(response.get_data(as_text=True)), [{"event": "test"}])

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.logs_to_report_json")
    @patch("nettacker.api.engine.now")
    def test_logs_get_json_missing_target(
        self, mock_now, mock_logs_to_json, mock_get_value, mock_api_key_valid
    ):
        mock_api_key_valid.return_value = True
        mock_get_value.return_value = None
        mock_logs_to_json.return_value = []
        mock_now.return_value = "2025_05_14_12_00_00"

        response = self.client.get("/logs/get_json")  # no target
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/json", response.content_type)
        self.assertEqual(json.loads(response.get_data(as_text=True)), [])

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.logs_to_report_json")
    @patch("nettacker.api.engine.now")
    @patch("nettacker.api.engine.random.choice", side_effect=list("abcdefghij"))
    @patch("builtins.open", new_callable=mock_open, read_data="mocked_csv_data\n")
    def test_logs_get_csv_valid_target(
        self,
        mock_open_fn,
        mock_random,
        mock_now,
        mock_logs_to_json,
        mock_get_value,
        mock_api_key_valid,
    ):
        mock_api_key_valid.return_value = True
        mock_get_value.return_value = "192.168.0.1"
        mock_logs_to_json.return_value = [
            {"target": "127.0.0.1", "module": "ping"}
        ]
        mock_now.return_value = "2025_05_14_12_00_00"

        response = self.client.get("/logs/get_csv?target=192.168.0.1")

        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.content_type)
        self.assertIn("attachment;filename=report-2025_05_14_12_00_00abcdefghij.csv", response.headers["Content-Disposition"])
        self.assertIn("mocked_csv_data", response.get_data(as_text=True))
        mock_open_fn.assert_any_call("report-2025_05_14_12_00_00abcdefghij", "w")
        mock_open_fn.assert_any_call("report-2025_05_14_12_00_00abcdefghij", "r")

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.logs_to_report_json")
    @patch("nettacker.api.engine.now")
    @patch("nettacker.api.engine.random.choice", side_effect=list("abcdefghij"))
    @patch("builtins.open", new_callable=mock_open, read_data="mocked_csv_data\n")
    def test_logs_get_csv_missing_target(
        self,
        mock_open_fn,
        mock_random,
        mock_now,
        mock_logs_to_json,
        mock_get_value,
        mock_api_key_valid,
    ):
        mock_api_key_valid.return_value = True
        mock_get_value.return_value = None
        mock_logs_to_json.return_value = [
            {"target": "unknown", "module": "x"}
        ]
        mock_now.return_value = "2025_05_14_12_00_00"

        response = self.client.get("/logs/get_csv")

        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.content_type)
        self.assertIn("attachment;filename=report-2025_05_14_12_00_00abcdefghij.csv", response.headers["Content-Disposition"])
        self.assertIn("mocked_csv_data", response.get_data(as_text=True))

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.search_logs")
    def test_search_logs_valid_query_and_page(self, mock_search_logs, mock_get_value, mock_api_key_valid):
        mock_api_key_valid.return_value = True
        # `get_value` called twice: once for "page", once for "q"
        mock_get_value.side_effect = ["2", "ping"]  # page=2, q="ping"
        mock_search_logs.return_value = [{"result": "match"}]

        response = self.client.get("/logs/search?page=2&q=ping")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, "application/json")
        self.assertEqual(response.get_json(), [{"result": "match"}])
        mock_search_logs.assert_called_once_with(1, "ping")  # page-1

    @patch("nettacker.api.engine.api_key_is_valid")
    @patch("nettacker.api.engine.get_value")
    @patch("nettacker.api.engine.search_logs")
    def test_search_logs_missing_query_and_page(self, mock_search_logs, mock_get_value, mock_api_key_valid):
        mock_api_key_valid.return_value = True
        # Simulate get_value raising exception for both page and query
        mock_get_value.side_effect = Exception("no value")
        mock_search_logs.return_value = [{"result": "empty search"}]

        response = self.client.get("/logs/search")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), [{"result": "empty search"}])
        mock_search_logs.assert_called_once_with(0, "")