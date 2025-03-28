import unittest
from unittest.mock import patch, mock_open

from nettacker.core.template import TemplateLoader


class TestTemplateLoader(unittest.TestCase):
    def test_parse_flat_dict(self):
        module_content = {"host": "localhost", "port": 80}
        inputs = {"host": "example.com"}
        expected_output = {"host": "example.com", "port": 80}
        result = TemplateLoader.parse(module_content, inputs)
        self.assertEqual(result, expected_output)

    def test_parse_nested_dict(self):
        module_content = {"connection": {"host": "localhost", "port": 80}, "timeout": 10}
        inputs = {"host": "example.com", "timeout": 20}
        expected_output = {"connection": {"host": "example.com", "port": 80}, "timeout": 20}
        result = TemplateLoader.parse(module_content, inputs)
        self.assertEqual(result, expected_output)

    def test_parse_with_list(self):
        content = [{"host": "localhost"}, {"port": 80}]
        inputs = {"host": "example.com"}
        result = TemplateLoader.parse(content, inputs)
        expected = [{"host": "example.com"}, {"port": 80}]
        self.assertEqual(result, expected)

    def test_parse_nested_list_dict(self):
        content = {
            "targets": [{"host": "localhost", "port": 80}, {"host": "localhost2", "port": 443}]
        }
        inputs = {"host": "example.com"}
        result = TemplateLoader.parse(content, inputs)
        expected = {
            "targets": [{"host": "example.com", "port": 80}, {"host": "example.com", "port": 443}]
        }
        self.assertEqual(result, expected)

    @patch("nettacker.config.Config.path.modules_dir")
    @patch("builtins.open", new_callable=mock_open, read_data="host: {host}\nport: {port}\n")
    def test_open(self, mock_file, mock_modules_dir):
        mock_modules_dir.__truediv__.return_value.__truediv__.return_value = "mock/path.yaml"
        loader = TemplateLoader("http_scan", {"host": "example.com"})
        result = loader.open()
        mock_file.assert_called_once_with("mock/path.yaml")
        self.assertEqual(result, "host: {host}\nport: {port}\n")

    @patch("nettacker.config.Config.path.modules_dir")
    @patch("builtins.open", new_callable=mock_open, read_data="host: {host}\nport: {port}\n")
    def test_format(self, mock_file, mock_modules_dir):
        mock_modules_dir.__truediv__.return_value.__truediv__.return_value = "dummy/path.yaml"
        loader = TemplateLoader("http_scan", {"host": "example.com", "port": 8080})
        result = loader.format()
        self.assertIn("example.com", result)
        self.assertIn("8080", result)

    @patch("nettacker.config.Config.path.modules_dir")
    @patch("builtins.open", new_callable=mock_open, read_data="host: {host}\nport: {port}\n")
    def test_load(self, mock_file, mock_modules_dir):
        mock_modules_dir.__truediv__.return_value.__truediv__.return_value = "dummy/path.yaml"
        loader = TemplateLoader("http_scan", {"host": "example.com", "port": 8080})
        result = loader.load()
        self.assertEqual(result, {"host": "example.com", "port": 8080})


if __name__ == "__main__":
    unittest.main()
