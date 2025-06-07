from unittest.mock import patch, mock_open, MagicMock

from nettacker.core.fuzzer import read_from_file
from tests.common import TestCase


class TestFuzzer(TestCase):
    @patch("nettacker.core.fuzzer.Config")
    @patch("builtins.open", new_callable=mock_open, read_data="line1\nline2\nline3\n")
    def test_read_from_file(self, mock_file, mock_config):
        test_path = "dummy.txt"
        mock_path = MagicMock()
        mock_path.__truediv__.return_value = "/mocked/path/dummy.txt"
        mock_config.path.payloads_dir = mock_path

        # Act
        result = read_from_file(test_path)

        # Assert
        mock_file.assert_called_once_with("/mocked/path/dummy.txt")
        self.assertEqual(result, ["line1", "line2", "line3", ""])
