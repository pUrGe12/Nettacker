import unittest
from unittest.mock import patch, MagicMock
from nettacker.core.lib.ftp import FtpLibrary

from tests.common import TestCase

class TestFtpLibrary(TestCase):

    @patch('nettacker.core.lib.ftp.FtpLibrary.client')
    def test_brute_force_success(self, mock_ftp_class):
        mock_ftp_instance = MagicMock()
        mock_ftp_class.return_value = mock_ftp_instance

        ftp_lib = FtpLibrary()
        result = ftp_lib.brute_force(
            host='127.0.0.1',
            port=21,
            username='user',
            password='pass',
            timeout=10
        )

        mock_ftp_class.assert_called_with(timeout=10)
        mock_ftp_instance.connect.assert_called_once_with('127.0.0.1', 21)
        mock_ftp_instance.login.assert_called_once_with('user', 'pass')
        mock_ftp_instance.close.assert_called_once()

        expected_result = {
            "host": '127.0.0.1',
            "port": 21,
            "username": 'user',
            "password": 'pass',
        }
        self.assertEqual(result, expected_result)