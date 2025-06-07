from unittest.mock import patch, MagicMock

from nettacker.core.lib.pop3 import Pop3Library
from tests.common import TestCase


class TestPop3Library(TestCase):
    @patch("nettacker.core.lib.pop3.Pop3Library.client")
    def test_brute_force_success(self, mock_pop3_client):
        # Setup mock instance
        mock_pop3_instance = MagicMock()
        mock_pop3_client.return_value = mock_pop3_instance

        pop3_lib = Pop3Library()
        result = pop3_lib.brute_force(
            host="127.0.0.1", port=110, username="user", password="pass", timeout=10
        )

        # Assertions
        mock_pop3_client.assert_called_with("127.0.0.1", port=110, timeout=10)
        mock_pop3_instance.user.assert_called_once_with("user")
        mock_pop3_instance.pass_.assert_called_once_with("pass")
        mock_pop3_instance.quit.assert_called_once()

        expected_result = {
            "host": "127.0.0.1",
            "port": 110,
            "username": "user",
            "password": "pass",
        }
        self.assertEqual(result, expected_result)
