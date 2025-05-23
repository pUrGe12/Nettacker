import unittest
import json
from unittest.mock import MagicMock, patch
from nettacker.core.module import Module


class TestModule(unittest.TestCase):
    def setUp(self):
        self.options = MagicMock()
        self.options.modules_extra_args = {"foo": "bar"}
        self.options.skip_service_discovery = False
        self.options.time_sleep_between_requests = 0
        self.options.thread_per_host = 2

        self.target = "127.0.0.1"
        self.scan_id = "scan123"
        self.process_number = 1
        self.thread_number = 1
        self.total_threads = 1

    @patch("nettacker.core.module.TemplateLoader")
    def test_init_and_service_discovery_signature(self, mock_loader):
        mock_instance = MagicMock()
        mock_instance.load.return_value = {
            "payloads": [
                {
                    "steps": [
                        {
                            "response": {
                                "conditions": {
                                    "service": {"http": {}}
                                }
                            }
                        }
                    ]
                }
            ]
        }
        mock_loader.return_value = mock_instance
        module = Module("port_scan", self.options, self.target, self.scan_id,
                        self.process_number, self.thread_number, self.total_threads)
        self.assertIn("http", module.service_discovery_signatures)

    @patch("nettacker.core.module.TemplateLoader")
    @patch("nettacker.core.module.find_events")
    @patch("os.listdir")
    def test_load_with_service_discovery(self, mock_listdir, mock_find_events, mock_loader):
        mock_listdir.return_value = ["http.py"]
        mock_loader_inst = MagicMock()
        mock_loader_inst.load.return_value = {
            "payloads": [
                {
                    "library": "http",
                    "steps": [
                        {
                            "response": {
                                "conditions": {
                                    "service": {"http": {}}
                                }
                            }
                        }
                    ]
                }
            ]
        }
        mock_loader.return_value = mock_loader_inst

        mock_find_events.return_value = [
            MagicMock(json_event='{"port": 80, "response": {"conditions_results": {"http": {}}}}')
        ]

        module = Module("test_module", self.options, self.target, self.scan_id,
                        self.process_number, self.thread_number, self.total_threads)
        module.load()
        self.assertEqual(module.discovered_services, {"http": [80]})
        self.assertEqual(len(module.module_content["payloads"]), 1)

    @patch("nettacker.core.module.find_events")
    @patch("nettacker.core.module.TemplateLoader")
    def test_sort_loops(self, mock_loader, mock_find_events):
        mock_loader_inst = MagicMock()
        mock_loader_inst.load.return_value = {
            "payloads": [
                {
                    "library": "http",
                    "steps": [
                        {"response": {"conditions": {"service": {}}}},
                        {"response": {
                            "conditions": {},
                            "dependent_on_temp_event": True,
                            "save_to_temp_events_only": True
                        }},
                        {"response": {
                            "conditions": {},
                            "dependent_on_temp_event": True
                        }},
                    ]
                }
            ]
        }
        mock_loader.return_value = mock_loader_inst

        # Mock find_events to return a fake port_scan result with "http"
        mock_event = MagicMock()
        mock_event.json_event = json.dumps({
            "port": 80,
            "response": {
                "conditions_results": {
                    "http": True
                }
            }
        })
        mock_find_events.return_value = [mock_event]

        module = Module("test_module", self.options, self.target, self.scan_id,
                        self.process_number, self.thread_number, self.total_threads)
        module.libraries = ["http"]
        module.load()  # Should no longer raise KeyError

    @patch("nettacker.core.module.find_events")
    @patch("nettacker.core.module.importlib.import_module")
    @patch("nettacker.core.module.wait_for_threads_to_finish")
    @patch("nettacker.core.module.time.sleep", return_value=None)
    @patch("nettacker.core.module.Thread")
    @patch("nettacker.core.module.TemplateLoader")
    def test_start_all_conditions(self, mock_loader, mock_thread, mock_sleep, mock_wait, mock_import, mock_find_events):
        engine_mock = MagicMock()
        mock_import.return_value = MagicMock(HttpEngine=MagicMock(return_value=engine_mock))

        mock_loader_inst = MagicMock()
        mock_loader_inst.load.return_value = {
            "payloads": [
                {
                    "library": "http",
                    "steps": [
                        {"step_id": 1, "response": {"conditions": {"service": {}}}}
                    ]
                }
            ]
        }
        mock_loader.return_value = mock_loader_inst

        # Mock find_events to return a fake port_scan result with "http"
        mock_event = MagicMock()
        mock_event.json_event = json.dumps({
            "port": 80,
            "response": {
                "conditions_results": {
                    "http": True
                }
            }
        })
        mock_find_events.return_value = [mock_event]

        module = Module("test_module", self.options, self.target, self.scan_id,
                        self.process_number, self.thread_number, self.total_threads)
        module.libraries = ["http"]
        module.load()
        module.start()
        # mock_thread.assert_called()
        mock_wait.assert_called()


    @patch("nettacker.core.module.find_events")
    @patch("nettacker.core.module.TemplateLoader")
    def test_start_unsupported_library(self, mock_loader, mock_find_events):
        # Payload uses an unsupported library "unsupported_lib"
        mock_loader_inst = MagicMock()
        mock_loader_inst.load.return_value = {
            "payloads": [
                {
                    "library": "unsupported_lib",
                    "steps": [
                        {"step_id": 1, "response": {"conditions": {"service": {}}}}
                    ]
                }
            ]
        }
        mock_loader.return_value = mock_loader_inst

        # Mock find_events to return a fake service discovery result for "unsupported_lib"
        mock_event = MagicMock()
        mock_event.json_event = json.dumps({
            "port": 1234,
            "response": {
                "conditions_results": {
                    "unsupported_lib": True
                }
            }
        })
        mock_find_events.return_value = [mock_event]

        module = Module("test_module", self.options, self.target, self.scan_id,
                        self.process_number, self.thread_number, self.total_threads)
        
        # Allow only "http" — not "unsupported_lib"
        module.libraries = ["http"]
        
        # This should run safely and skip the unsupported payload
        module.service_discovery_signatures.append("unsupported_lib")  # Add this line

        module.load()
        result = module.start()
        self.assertIsNone(result)
