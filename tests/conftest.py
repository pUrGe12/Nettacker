import sys
import pathlib
import types
from os.path import abspath, dirname, join
import pytest
from unittest.mock import Mock
import builtins

# ========== Your original path injection ==========
project_root = dirname(dirname(__file__))
nettacker_dir = abspath(join(project_root, "nettacker"))
tests_dir = abspath(join(project_root, "tests"))

sys.path.insert(0, nettacker_dir)
sys.path.insert(1, tests_dir)

# ========== Global fast mocks to prevent I/O ==========
@pytest.fixture(autouse=True)
def mock_nettacker_dependencies(monkeypatch):
    # Step 1: Ensure arg_parser is re-imported clean
    if "nettacker.core.arg_parser" in sys.modules:
        del sys.modules["nettacker.core.arg_parser"]

    # Step 2: Patch Config to only return 1 fake module, lang, graph
    from nettacker import config as real_config

    class FakeGlob:
        def __init__(self, paths):
            self._paths = paths
        def glob(self, pattern):
            return self._paths

    fake_module_path = pathlib.Path("ping/discovery.yaml")
    fake_locale_path = pathlib.Path("en.yaml")
    fake_graph_path = pathlib.Path("graph/engine.py")

    monkeypatch.setattr(real_config.Config.path, "modules_dir", FakeGlob([fake_module_path]))
    monkeypatch.setattr(real_config.Config.path, "locale_dir", FakeGlob([fake_locale_path]))
    monkeypatch.setattr(real_config.Config.path, "graph_dir", FakeGlob([fake_graph_path]))

    # Step 3: Patch TemplateLoader.open to return mock YAML
    monkeypatch.setattr("nettacker.core.template.TemplateLoader.open", lambda self: "info:\n  profiles:\n    - scan\npayload:")

    # Step 4: Patch yaml.safe_load to return dummy parsed content
    import yaml
    monkeypatch.setattr(yaml, "safe_load", lambda _: {"info": {"profiles": ["scan"]}})

    # Step 5: Patch dictionary sorter
    from nettacker.core.utils import common
    monkeypatch.setattr(common, "sort_dictionary", lambda d: d)

    # Step 6: Silence logger
    import nettacker.logger
    monkeypatch.setattr(nettacker.logger, "get_logger", lambda: Mock(
        info=Mock(),
        error=Mock(),
        warn=Mock(),
        write=Mock(),
        reset_color=Mock()
    ))

    # Step 7: Patch open to avoid recursion
    original_open = builtins.open
    def safe_open(file, *args, **kwargs):
        if str(file).endswith("user_agents.txt"):
            return Mock(read=lambda: "UA1\nUA2")
        if str(file).endswith(".txt") or str(file).endswith(".yaml"):
            return Mock(read=lambda: "127.0.0.1\n", readlines=lambda: ["127.0.0.1\n"], __enter__=lambda s: s, __exit__=lambda *a: None)
        return original_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", safe_open)

    yield
