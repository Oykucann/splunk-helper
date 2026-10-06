"""Static guard: the remote collector must be read-only and Python 3.7 compatible (ADR-0001)."""

import ast
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "src" / "shx" / "remote" / "collect_remote.py"

FORBIDDEN_IMPORTS = {"shutil", "pathlib", "urllib", "http", "requests", "ftplib", "smtplib",
                     "telnetlib", "tempfile", "sqlite3", "multiprocessing", "ctypes"}
FORBIDDEN_OS_CALLS = {
    "remove", "unlink", "rmdir", "removedirs", "rename", "renames", "replace", "mkdir",
    "makedirs", "chmod", "lchmod", "chown", "lchown", "symlink", "link", "truncate",
    "ftruncate", "kill", "killpg", "system", "popen", "fork", "utime", "write", "open",
    "mkfifo", "mknod", "setuid", "setgid", "putenv", "unsetenv", "chdir",
}
ALLOWED_OPEN_MODES = {"r", "rb"}


def _tree():
    return ast.parse(SCRIPT.read_text(), feature_version=(3, 7))


def _enclosing_functions(tree):
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def chain(node):
        names = []
        while node in parents:
            node = parents[node]
            if isinstance(node, ast.FunctionDef):
                names.append(node.name)
        return names

    return chain


def test_parses_as_python37():
    _tree()


def test_no_forbidden_imports():
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Import):
            names = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [(node.module or "").split(".")[0]]
        else:
            continue
        assert not set(names) & FORBIDDEN_IMPORTS, f"forbidden import at line {node.lineno}"


def test_open_is_read_only():
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            mode = node.args[1] if len(node.args) > 1 else next(
                (k.value for k in node.keywords if k.arg == "mode"), None)
            assert isinstance(mode, ast.Constant) and mode.value in ALLOWED_OPEN_MODES, (
                f"open() at line {node.lineno} must use an explicit read-only mode")


def test_no_mutating_os_calls():
    for node in ast.walk(_tree()):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "os"):
            name = node.func.attr
            assert name not in FORBIDDEN_OS_CALLS and not name.startswith(("exec", "spawn")), (
                f"os.{name} at line {node.lineno} is not allowed")


def test_subprocess_only_in_run_btool_and_only_btool():
    tree = _tree()
    chain = _enclosing_functions(tree)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Attribute)
             and isinstance(n.value, ast.Name) and n.value.id == "subprocess"
             and n.attr not in ("DEVNULL", "PIPE")]
    assert calls, "expected the btool subprocess call"
    for node in calls:
        assert chain(node)[:1] == ["_run_btool"], f"subprocess use at line {node.lineno}"
    run_calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute) and n.func.attr == "run"
                 and isinstance(n.func.value, ast.Name) and n.func.value.id == "subprocess"]
    assert len(run_calls) == 1
    argv = run_calls[0].args[0]
    assert isinstance(argv, ast.List)
    assert isinstance(argv.elts[1], ast.Constant) and argv.elts[1].value == "btool"
    assert isinstance(argv.elts[3], ast.Constant) and argv.elts[3].value == "list"


def test_tar_only_written_to_a_stream():
    for node in ast.walk(_tree()):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "open" and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "tarfile"):
            assert not node.args, "tarfile.open must not take a filename"
            kw = {k.arg: k.value for k in node.keywords}
            assert "fileobj" in kw and "name" not in kw
            assert isinstance(kw["mode"], ast.Constant) and kw["mode"].value == "w|gz"


def test_no_network_sockets():
    for node in ast.walk(_tree()):
        if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                and node.value.id == "socket"):
            assert node.attr in ("gethostname", "getfqdn"), f"socket.{node.attr} at {node.lineno}"
