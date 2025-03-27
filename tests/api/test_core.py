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
from tests.common import TestCase
from werkzeug.exceptions import NotFound


class TestCore(TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["OWASP_NETTACKER_CONFIG"] = {"api_access_key": "test_key"}
        self.request = MagicMock(spec=Request)
        self.request.args = {"key": "test_key"}
        self.request.form = {"key_form": "form_key"}
        self.request.cookies = {"key_cookies": "cookies"}
        self.mock_web_static_dir = '/mock/web/static/dir'
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
        mock_filename = os.path.join(self.mock_web_static_dir, 'test.txt')
        mock_content = b'test file content'
        
        with patch('os.path.normpath', return_value=mock_filename), \
             patch('builtins.open', unittest.mock.mock_open(read_data=mock_content)) as mock_file:
            
            result = get_file(mock_filename)
            self.assertEqual(result, mock_content)
            mock_file.assert_called_once_with(mock_filename, 'rb')

    def test_file_outside_static_dir(self):
        unsafe_filename = '/etc/passwd'
        
        with patch('os.path.normpath', return_value=unsafe_filename):
            with self.assertRaises(NotFound):
                get_file(unsafe_filename)

    def test_value_error_handling(self):
        mock_filename = os.path.join(self.mock_web_static_dir, 'test.txt')
        
        with patch('os.path.normpath', return_value=mock_filename), \
             patch('builtins.open', side_effect=ValueError):
            
            with self.assertRaises(NotFound):
                get_file(mock_filename)

    def test_io_error_handling(self):
        mock_filename = os.path.join(self.mock_web_static_dir, 'test.txt')
        
        with patch('os.path.normpath', return_value=mock_filename), \
             patch('builtins.open', side_effect=IOError):
            
            with self.assertRaises(NotFound):
                get_file(mock_filename)

    def test_file_not_found(self):
        mock_filename = os.path.join(self.mock_web_static_dir, 'nonexistent.txt')
        
        with patch('os.path.normpath', return_value=mock_filename), \
             patch('builtins.open', side_effect=FileNotFoundError):
            
            with self.assertRaises(NotFound):
                get_file(mock_filename)

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