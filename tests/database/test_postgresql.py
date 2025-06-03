import unittest
from unittest.mock import patch, MagicMock
from sqlalchemy.exc import OperationalError
from sqlalchemy import text

from nettacker.database.postgresql import postgres_create_database
from nettacker.config import Config
from tests.common import TestCase


class TestPostgreSQL(TestCase):

    @patch('nettacker.database.postgresql.create_engine')
    @patch('nettacker.database.postgresql.Base.metadata.create_all')
    def test_postgresql_create_database_success(self, mock_create_all, mock_create_engine):
        Config.db = MagicMock()
        Config.db.as_dict.return_value = {
            'username': 'test_user',
            'password': 'test_pass',
            'host': 'localhost',
            'port': '5432',
            'name': 'test_db'
        }

        mock_engine = MagicMock()
        mock_create_engine.return_value = mock_engine

        postgres_create_database()

        mock_create_engine.assert_called_with(
            "postgresql+psycopg2://test_user:test_pass@localhost:5432/test_db"
        )
        mock_create_all.assert_called_once_with(mock_engine)

    @patch('nettacker.database.postgresql.create_engine')
    @patch('nettacker.database.postgresql.Base.metadata.create_all')
    def test_postgresql_create_database_missing_db_creates_it(self, mock_create_all, mock_create_engine):
        Config.db = MagicMock()
        Config.db.name = 'test_db'
        Config.db.as_dict.return_value = {
            'username': 'test_user',
            'password': 'test_pass',
            'host': 'localhost',
            'port': '5432',
            'name': 'test_db'
        }

        mock_create_all.side_effect = [OperationalError("fail", None, None), None]

        fallback_conn = MagicMock()
        fallback_conn.execution_options.return_value = fallback_conn

        first_engine = MagicMock()
        fallback_engine = MagicMock()
        fallback_engine.connect.return_value = fallback_conn
        final_engine = MagicMock()

        mock_create_engine.side_effect = [
            first_engine,
            fallback_engine,
            final_engine
        ]

        postgres_create_database()

        fallback_conn.execute.assert_called_once()
        sql_arg = fallback_conn.execute.call_args[0][0]
        assert str(sql_arg) == "CREATE DATABASE test_db"
        assert mock_create_all.call_count == 2  # one failed, one success

    @patch('nettacker.database.postgresql.create_engine')
    @patch('nettacker.database.postgresql.Base.metadata.create_all')
    def test_postgresql_create_database_operational_error_on_fallback(self, mock_create_all, mock_create_engine):
        Config.db = MagicMock()
        Config.db.name = 'test_db'
        Config.db.as_dict.return_value = {
            'username': 'test_user',
            'password': 'test_pass',
            'host': 'localhost',
            'port': '5432',
            'name': 'test_db'
        }

        mock_create_all.side_effect = OperationalError("fail", None, None)

        # For a total of 3 attempts, we add it thrice
        failing_engine = MagicMock()
        mock_create_engine.side_effect = [failing_engine, failing_engine, failing_engine]

        # Should raise error as the function doesn't handle it explicitly
        with self.assertRaises(OperationalError):
            postgres_create_database()