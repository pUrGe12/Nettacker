import unittest
from unittest.mock import patch, MagicMock
from nettacker.core.lib.smtp import SmtpLibrary

from tests.common import TestCase


class TestSmtpLibrary(TestCase):

    @patch('nettacker.core.lib.smtp.SmtpLibrary.client')
    def test_brute_force_success(self, mock_smtp_client):
        mock_smtp_instance = MagicMock()
        mock_smtp_client.return_value = mock_smtp_instance

        smtp_lib = SmtpLibrary()
        result = smtp_lib.brute_force(
            host='127.0.0.1',
            port=25,
            username='user',
            password='pass',
            timeout=10
        )

        mock_smtp_client.assert_called_with('127.0.0.1', 25, timeout=10)
        mock_smtp_instance.login.assert_called_once_with('user', 'pass')
        mock_smtp_instance.close.assert_called_once()

        expected_result = {
            "host": '127.0.0.1',
            "port": 25,
            "username": 'user',
            "password": 'pass',
        }
        self.assertEqual(result, expected_result)
