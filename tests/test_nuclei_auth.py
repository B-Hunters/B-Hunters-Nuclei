"""The session headers reach nuclei.

A scan can name an identity: the task carries the identity's cookies and
headers, and the worker has to hand them to nuclei, because a target
that needs a session answers an anonymous request with a login page.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import nucleim.nucleim as nucleim_module  # noqa: E402
from nucleim.nucleim import nucleim  # noqa: E402


class _Task:
    """A task that carries nothing but a payload."""

    def __init__(self, payload: Any) -> None:
        self.payload = payload


class _Worker(nucleim):
    """A worker without a configuration file and without a database."""

    def __init__(self) -> None:
        pass


class _Pipe:
    """The end of a pipe nuclei's output would come from."""

    def read(self) -> bytes:
        return b""

    def write(self, data: bytes) -> int:
        return len(data)

    def close(self) -> None:
        pass


class _Process:
    """The process nuclei's output would come from."""

    stdin = _Pipe()
    stdout = _Pipe()

    def communicate(self, *args: Any, **kwargs: Any) -> tuple[bytes, None]:
        return b"", None


class _Subprocess:
    """A subprocess module that records the commands instead of running them."""

    PIPE = subprocess.PIPE

    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def Popen(self, argv: list[str], **kwargs: Any) -> _Process:
        self.commands.append(argv)
        return _Process()


def _worker(monkeypatch: Any) -> tuple[_Worker, _Subprocess]:
    worker = _Worker()
    subprocess = _Subprocess()
    monkeypatch.setattr(nucleim_module, "subprocess", subprocess)
    return worker, subprocess


def test_the_session_headers_reach_nuclei(monkeypatch: Any) -> None:
    worker, subprocess = _worker(monkeypatch)
    task = _Task(payload={"auth": {"cookies": {"JSESSIONID": "abc"}, "headers": {"X-Test": "1"}}})

    worker.nucleiscansingle("http://example.test", worker.auth_headers(task))

    assert "-H" in subprocess.commands[0]
    assert "X-Test: 1" in subprocess.commands[0]
    assert "Cookie: JSESSIONID=abc" in subprocess.commands[0]


def test_nuclei_gets_no_header_without_an_identity(monkeypatch: Any) -> None:
    worker, subprocess = _worker(monkeypatch)
    task = _Task(payload={})

    worker.nucleiscansingle("http://example.test", worker.auth_headers(task))

    assert "-H" not in subprocess.commands[0]


def test_the_session_headers_reach_the_url_list_scan(monkeypatch: Any) -> None:
    worker, subprocess = _worker(monkeypatch)
    worker.subdomain = "example.test"
    monkeypatch.setattr(
        worker, "checklinksexist", lambda subdomain, links: ["http://example.test/?a=1"]
    )
    task = _Task(payload={"auth": {"headers": {"X-Test": "1"}}})

    worker.nucleiscanfile(b"http://example.test/?a=1\n", worker.auth_headers(task))

    scan = [command for command in subprocess.commands if command[0] == "nuclei"]
    assert scan, "the URL list was not scanned"
    assert "X-Test: 1" in scan[0]


def test_the_url_list_scan_gets_no_header_without_an_identity(monkeypatch: Any) -> None:
    worker, subprocess = _worker(monkeypatch)
    worker.subdomain = "example.test"
    monkeypatch.setattr(
        worker, "checklinksexist", lambda subdomain, links: ["http://example.test/?a=1"]
    )
    task = _Task(payload={})

    worker.nucleiscanfile(b"http://example.test/?a=1\n", worker.auth_headers(task))

    scan = [command for command in subprocess.commands if command[0] == "nuclei"]
    assert scan, "the URL list was not scanned"
    assert "-H" not in scan[0]
