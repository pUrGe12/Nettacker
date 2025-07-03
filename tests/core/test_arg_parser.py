"""
Every branch in arg_parser.py is hit at least once.

The helper `run` wraps an ArgParser invocation, taking care of
  • injecting sys.argv
  • catching DieFailure / DieSuccess
"""
import importlib
import io
import sys
import builtins
import pytest

# Exceptions raised by our fake die_* functions
from nettacker.core.die import die_failure, die_success


def _reload_parser():
    """Import arg_parser *fresh* so Config mutations don’t leak."""
    mod_name = "nettacker.core.arg_parser"
    if mod_name in sys.modules:          # drop cached copy
        del sys.modules[mod_name]
    return importlib.import_module(mod_name).ArgParser



# --------------------------------------------------------------------------- #
#  Helper that drives ArgParser and asserts outcome
# --------------------------------------------------------------------------- #
def run(argv, expect_fail=None, expect_success=False, monkeypatch=None):
    sys.argv = ["nettacker", *argv]
    Parser = _reload_parser()

    if expect_fail or expect_success:
        with pytest.raises(SystemExit) as exc:
            Parser()
        if expect_fail:
            assert exc.value.code == 1
        if expect_success:
            assert exc.value.code == 0
        return None

    return Parser()
    
# --------------------------------------------------------------------------- #
#  BASIC EARLY‑EXIT FLAGS
# --------------------------------------------------------------------------- #
def test_help(monkeypatch):
    run(["-h"], expect_success=True)


def test_version(monkeypatch):
    run(["-V"], expect_success=True)


def test_show_all_modules(monkeypatch):
    run(["--show-all-modules"], expect_success=True)


def test_show_all_profiles(monkeypatch):
    run(["--show-all-profiles"], expect_success=True)


def test_invalid_language(monkeypatch):
    run(["-L", "fr", "-i", "1.1.1.1", "-m", "ping"], expect_fail="Please select")


# --------------------------------------------------------------------------- #
#  TARGET & MODULE HANDLING
# --------------------------------------------------------------------------- #
def test_missing_target(monkeypatch):
    run(["-m", "ping"], expect_fail="error_target")


def test_invalid_module(monkeypatch):
    run(["-i", "1.1.1.1", "-m", "badmod"], expect_fail="scan_module_not_found")


def test_all_modules_shortcut(monkeypatch):
    p = run(["-i", "1.1.1.1", "-m", "all"])
    # our fake env only has *one* module
    assert p.arguments.selected_modules == ["ping_discovery"]


def test_profile_success(monkeypatch):
    p = run(["-i", "1.1.1.1", "--profile", "scan"])
    assert "ping_discovery" in p.arguments.selected_modules


def test_profile_not_found(monkeypatch):
    run(["-i", "1.1.1.1", "--profile", "ghost"], expect_fail="profile_404")


# --------------------------------------------------------------------------- #
#  HARDWARE‑USAGE & THREAD SANITY
# --------------------------------------------------------------------------- #
def test_hardware_usage_bad(monkeypatch):
    run(
        ["-i", "1.1.1.1", "-m", "ping", "--set-hardware-usage", "ultra"],
        expect_fail="wrong_hardware_usage",
    )


def test_threads_auto_fix(monkeypatch):
    p = run(["-i", "1.1.1.1", "-m", "ping", "-t", "0", "-M", "0"])
    assert p.arguments.thread_per_host == 1 and p.arguments.parallel_module_scan == 1


# --------------------------------------------------------------------------- #
#  EXCLUDE MODULES
# --------------------------------------------------------------------------- #
def test_exclude_all(monkeypatch):
    run(["-i", "1.1.1.1", "-m", "ping", "-x", "all"], expect_fail="error_exclude_all")


def test_exclude_specific(monkeypatch):
    p = run(["-i", "1.1.1.1", "-m", "ping", "-x", "ping_discovery"])
    assert "ping_discovery" not in p.arguments.selected_modules


# --------------------------------------------------------------------------- #
#  PORT PARSER
# --------------------------------------------------------------------------- #
def test_port_range_ok(monkeypatch):
    p = run(["-i", "1.1.1.1", "-m", "ping", "-g", "80-82,443"])
    assert p.arguments.ports == [80, 81, 82, 443]


def test_port_bad(monkeypatch):
    run(["-i", "1.1.1.1", "-m", "ping", "-g", "80,abc"], expect_fail="ports_int")


# --------------------------------------------------------------------------- #
#  RANDOM USER‑AGENT PATH
# --------------------------------------------------------------------------- #
def test_random_user_agent(monkeypatch):
    monkeypatch.setattr(
        builtins,
        "open",
        lambda *a, **k: io.StringIO("UA1\nUA2\n")
        if a[0] == "user_agents.txt"
        else builtins.open(*a, **k),
    )
    p = run(["-i", "1.1.1.1", "-m", "ping", "--user-agent", "random_user_agent"])
    assert p.arguments.user_agents == ["UA1", "UA2"]


# --------------------------------------------------------------------------- #
#  FILE‑BASED FLAGS (error branches)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "flag, path, err_key",
    [
        ("--users-list", "missing_users.txt", "error_username"),
        ("--passwords-list", "missing_pw.txt", "error_passwords"),
        ("-W", "missing_wordlist.txt", "error_wordlist"),
        ("-l", "missing_targets.txt", "error_target_file"),
    ],
)
def test_missing_files(monkeypatch, flag, path, err_key):
    run(["-i", "1.1.1.1", "-m", "ping", flag, path], expect_fail=err_key)


def test_output_write_fail(monkeypatch):
    # make *only* this filename raise IOError
    monkeypatch.setattr(
        builtins,
        "open",
        lambda fname, mode="r", *a, **k: (
            (_ for _ in ()).throw(IOError("boom"))
            if fname == "/nowhere/out.html" and "w" in mode
            else builtins.open(fname, mode, *a, **k)
        ),
    )
    run(
        ["-i", "1.1.1.1", "-m", "ping", "-o", "/nowhere/out.html"],
        expect_fail="file_write_error",
    )


# --------------------------------------------------------------------------- #
#  GRAPH OPTIONS
# --------------------------------------------------------------------------- #
def test_bad_graph(monkeypatch):
    run(
        ["-i", "1.1.1.1", "-m", "ping", "--graph", "nope_graph"],
        expect_fail="graph_module_404",
    )


def test_graph_warn_extension(monkeypatch):
    p = run(
        ["-i", "1.1.1.1", "-m", "ping", "--graph", "d3_tree_graph", "-o", "out.txt"]
    )
    assert p.arguments.graph_name is None  # was nulled after warn


# --------------------------------------------------------------------------- #
#  MODULE EXTRA ARGS PARSER
# --------------------------------------------------------------------------- #
def test_modules_extra_args(monkeypatch):
    p = run(
        [
            "-i",
            "1.1.1.1",
            "-m",
            "ping",
            "--modules-extra-args",
            "rate=1.5&debug=false&num=5&conf={\"a\":1}",
        ]
    )
    d = p.arguments.modules_extra_args
    assert d == {"rate": 1.5, "debug": False, "num": 5, "conf": {"a": 1}}


# --------------------------------------------------------------------------- #
#  API SERVER BRANCHES
# --------------------------------------------------------------------------- #
def test_start_api_ok(monkeypatch):
    p = run(
        [
            "-i",
            "1.1.1.1",
            "-m",
            "ping",
            "--start-api",
            "--api-client-whitelisted-ips",
            "127.0.0.1,10.0.0.0-10.0.0.1",
        ]
    )
    assert p.arguments.api_client_whitelisted_ips[0] == "127.0.0.1"


def test_start_api_from_web(monkeypatch):
    # simulate call *from* the API (api_arguments supplied)
    Parser = _reload_parser()
    with pytest.raises(die_failure) as exc:
        Parser(api_arguments={})  # sys.argv still has no --start-api
    # now actually provide the flag, should raise cannot_run_api_server
    sys.argv = ["nettacker", "--start-api"]
    with pytest.raises(die_failure) as exc:
        Parser(api_arguments={})
    assert "cannot_run_api_server" in str(exc.value)
