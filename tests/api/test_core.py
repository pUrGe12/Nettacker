import unittest
import os
from unittest.mock import patch, MagicMock
from flask import Flask, Request
from nettacker.core.messages import messages as _
from nettacker.api.core import (
    get_value, mime_types, get_file, api_key_is_valid, languages_to_country, graphs, profiles, scan_methods
)
from nettacker.config import Config
from nettacker.core.app import Nettacker

# I remember this being so much more robust. We'll have to make it robust. Later though, let's sort the other test cases first
# Atleast I have something here.

class TestCore(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["OWASP_NETTACKER_CONFIG"] = {"api_access_key": "test_key"}
        self.request = MagicMock(spec=Request)
        self.request.args = {"key": "test_key"}
        self.request.form = {}
        self.request.cookies = {}

    def test_get_value(self):
        self.assertEqual(get_value(self.request, "key"), "test_key")
        self.assertEqual(get_value(self.request, "nonexistent"), "")

    def test_mime_types(self):
        mtypes = mime_types()
        self.assertIn(".html", mtypes)
        self.assertEqual(mtypes[".html"], "text/html")

    @patch("builtins.open", new_callable=unittest.mock.mock_open, read_data="test_data")
    def test_get_file_valid(self, mock_open):
        Config.path.web_static_dir = os.getcwd()
        filename = os.path.join(Config.path.web_static_dir, "test.txt")
        self.assertEqual(get_file(filename), "test_data")

    @patch("builtins.open", side_effect=IOError)
    def test_get_file_invalid(self, mock_open):
        with self.assertRaises(Exception):
            get_file("invalid.txt")

    def test_api_key_is_valid(self):
        with self.app.test_request_context():
            api_key_is_valid(self.app, self.request)  # Should not raise an error

    def test_api_key_invalid(self):
        self.request.args = {"key": "wrong_key"}
        with self.assertRaises(Exception):
            api_key_is_valid(self.app, self.request)

    @patch("nettacker.core.app.Nettacker.load_graphs", return_value=["graph1", "graph2"])
    def test_graphs(self, mock_graphs):
        result = graphs()
        self.assertIn("graph1", result)
        self.assertIn("graph2", result)

    @patch("nettacker.core.app.Nettacker.load_profiles", return_value={"scan": {}, "brute": {}})
    def test_profiles(self, mock_profiles):
        result = profiles()
        self.assertIn("scan", result)
        self.assertIn("brute", result)

    @patch("nettacker.core.app.Nettacker.load_modules", return_value={"port_scan": {}, "all": {}})
    def test_scan_methods(self, mock_methods):
        result = scan_methods()
        self.assertIn("port_scan", result)
        self.assertNotIn("all", result)

    @patch("nettacker.core.messages.get_languages", return_value=["en", "fr"])
    def test_languages_to_country(self, mock_langs):
        result = languages_to_country()
        self.assertIn("en", result)
        self.assertIn("fr", result)