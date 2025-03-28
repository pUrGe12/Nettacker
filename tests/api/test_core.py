import os
import unittest
from unittest.mock import patch, MagicMock

from bs4 import BeautifulSoup
from flask import Flask, Request
from werkzeug.exceptions import NotFound

from nettacker.api.core import (
    get_value,
    mime_types,
    get_file,
    api_key_is_valid,
    languages_to_country,
    graphs,
    profiles,
    scan_methods,
)
from nettacker.config import Config
from tests.common import TestCase


class TestCore(TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["OWASP_NETTACKER_CONFIG"] = {"api_access_key": "test_key"}
        self.request = MagicMock(spec=Request)
        self.request.args = {"key": "test_key"}
        self.request.form = {"key_form": "form_key"}
        self.request.cookies = {"key_cookies": "cookies"}
        self.mock_web_static_dir = "/mock/web/static/dir"
        Config.path.web_static_dir = self.mock_web_static_dir

    def test_get_value(self):
        self.assertEqual(get_value(self.request, "key"), "test_key")
        self.assertEqual(get_value(self.request, "key_form"), "form_key")
        self.assertEqual(get_value(self.request, "key_cookies"), "cookies")
        self.assertEqual(get_value(self.request, "key_not_present"), "")

    def test_mime_types(self):
        mtypes = mime_types()
        self.assertEqual(len(list(mtypes.keys())), 69)
        self.assertIn(".html", mtypes)
        self.assertEqual(mtypes[".html"], "text/html")

    def test_successful_file_retrieval(self):
        mock_filename = os.path.join(self.mock_web_static_dir, "test.txt")
        mock_content = b"test file content"

        with patch("os.path.normpath", return_value=mock_filename), patch(
            "builtins.open", unittest.mock.mock_open(read_data=mock_content)
        ) as mock_file:
            result = get_file(mock_filename)
            self.assertEqual(result, mock_content)
            mock_file.assert_called_once_with(mock_filename, "rb")

    def test_file_outside_static_dir(self):
        unsafe_filename = "/etc/passwd"

        with patch("os.path.normpath", return_value=unsafe_filename):
            with self.assertRaises(NotFound):
                get_file(unsafe_filename)

    def test_value_error_handling(self):
        mock_filename = os.path.join(self.mock_web_static_dir, "test.txt")

        with patch("os.path.normpath", return_value=mock_filename), patch(
            "builtins.open", side_effect=ValueError
        ):
            with self.assertRaises(NotFound):
                get_file(mock_filename)

    def test_io_error_handling(self):
        mock_filename = os.path.join(self.mock_web_static_dir, "test.txt")

        with patch("os.path.normpath", return_value=mock_filename), patch(
            "builtins.open", side_effect=IOError
        ):
            with self.assertRaises(NotFound):
                get_file(mock_filename)

    def test_file_not_found(self):
        mock_filename = os.path.join(self.mock_web_static_dir, "nonexistent.txt")

        with patch("os.path.normpath", return_value=mock_filename), patch(
            "builtins.open", side_effect=FileNotFoundError
        ):
            with self.assertRaises(NotFound):
                get_file(mock_filename)

    def test_api_key_is_valid(self):
        with self.app.test_request_context():
            api_key_is_valid(self.app, self.request)  # Should not raise an error

    def test_api_key_invalid(self):
        self.request.args = {"key": "wrong_key"}
        with self.assertRaises(Exception):
            api_key_is_valid(self.app, self.request)

    @patch(
        "nettacker.core.app.Nettacker.load_graphs",
        return_value=["d3_tree_v1_graph", "d3_tree_v2_graph"],
    )
    def test_graphs(self, mock_graphs):
        """
        Mocking load_graphs and returning d3_tree_v1_graph and d3_tree_v2_graph in a list, which are the real names that are expected to be returned.
        Parsing it using BeautifulSoup and verifying IDs (it might be none too for which an empty string is used to validate)
        """
        result = graphs()
        soup = BeautifulSoup(result, "html.parser")
        inputs = soup.find_all("input", {"type": "radio", "name": "graph_name"})
        input_ids = {tag["id"] for tag in inputs}
        self.assertSetEqual(input_ids, {"d3_tree_v1_graph", "d3_tree_v2_graph", ""})

    @patch("nettacker.core.app.Nettacker.load_profiles", return_value={"scan": {}, "brute": {}})
    def test_profiles(self, mock_profiles):
        result = profiles()
        soup = BeautifulSoup(result, "html.parser")

        inputs = soup.find_all("input", {"type": "checkbox"})
        input_ids = {tag["id"] for tag in inputs}
        labels = {
            tag.text.strip()
            for tag in soup.find_all("a", {"class": lambda x: x and "label-" in x})
        }
        expected_profiles = {"scan", "brute"}

        self.assertSetEqual(input_ids, expected_profiles)
        self.assertSetEqual(labels, expected_profiles)

    @patch(
        "nettacker.core.app.Nettacker.load_modules",
        return_value={"port_scan": {}, "dir_scan": {}, "all": {}},
    )
    def test_scan_methods(self, mock_methods):
        """load profiles explicitly removes 'all' before returning. Making use of that to assert."""
        result = scan_methods()
        soup = BeautifulSoup(result, "html.parser")

        inputs = soup.find_all("input", {"type": "checkbox"})
        input_ids = {tag.get("id", "").strip() for tag in inputs}
        expected_ids = {"port_scan", "dir_scan"}

        self.assertEqual(input_ids, expected_ids)
        self.assertNotIn("all", result)

    @patch("nettacker.core.messages.get_languages", return_value=["en", "fr"])
    def test_languages_to_country(self, mock_langs):
        """
        Returning english and french. Asserting that the IDs of the HTML content are in ["en", "fr"].
        Verifying the data-content attribute and the selected language, which is "en" by default.
        """
        result = languages_to_country()
        soup = BeautifulSoup(result, "html.parser")

        options = soup.find_all("option")
        self.assertEqual(len(options), 2)

        option_ids = {opt.get("id") for opt in options}
        self.assertSetEqual(option_ids, {"en", "fr"})

        for opt in options:
            lang = opt.get("id")
            self.assertIn(f"flag-icon-{ {'en': 'us', 'fr': 'fr'}[lang] }", opt.get("data-content"))
        selected_options = [opt for opt in options if opt.has_attr("selected")]
        self.assertEqual(len(selected_options), 1)
        self.assertEqual(selected_options[0].get("id"), "en")
