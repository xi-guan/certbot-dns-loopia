"""
Tests for certbot-dns-loopia
"""
# pylint: disable=protected-access,redefined-outer-name,invalid-name
import itertools
import socket
import threading
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Dict, Iterable, Iterator, List, Tuple
from unittest.mock import MagicMock
from xmlrpc.server import SimpleXMLRPCServer

import pytest
from certbot.errors import PluginError

import certbot_dns_loopia
from certbot_dns_loopia import LoopiaAuthenticator, LoopiaClient

USER = "test@loopiaapi"
# quoted in the INI file, otherwise configobj cuts the value at "#" (issue #42)
PASSWORD = "pass#word"


class FakeLoopia(ThreadingMixIn, SimpleXMLRPCServer):
    """
    Loopia XML-RPC API on localhost that keeps zone records in memory.
    """

    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), logRequests=False)
        self.zones: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        self.calls: List[str] = []
        #: Number of upcoming calls that hang until the test ends
        self.stalls = 0
        self.unstall = threading.Event()
        self._ids = itertools.count(1)

    @property
    def url(self) -> str:
        """
        URL of the API endpoint.
        """
        return f"http://127.0.0.1:{self.server_address[1]}/RPC2"

    def _dispatch(self, method: str, params: Iterable[Any]) -> Any:
        self.calls.append(method)
        if self.stalls:
            self.stalls -= 1
            self.unstall.wait(10)

        user, password, *args = params
        if (user, password) != (USER, PASSWORD):
            return ["AUTH_ERROR"] if method == "getZoneRecords" else "AUTH_ERROR"
        return getattr(self, method)(*args)

    def addZoneRecord(self, domain: str, subdomain: str, record: Dict[str, Any]) -> str:
        """
        See https://www.loopia.com/api/addzonerecord/
        """
        records = self.zones.setdefault((domain, subdomain), [])
        records.append(dict(record, record_id=next(self._ids)))
        return "OK"

    def getZoneRecords(self, domain: str, subdomain: str) -> List[Dict[str, Any]]:
        """
        See https://www.loopia.com/api/getzonerecords/
        """
        return self.zones.get((domain, subdomain), [])

    def removeZoneRecord(self, domain: str, subdomain: str, record_id: int) -> str:
        """
        See https://www.loopia.com/api/removezonerecord/
        """
        records = self.zones.get((domain, subdomain), [])
        self.zones[domain, subdomain] = [r for r in records if r["record_id"] != record_id]
        return "OK"

    def removeSubdomain(self, domain: str, subdomain: str) -> str:
        """
        See https://www.loopia.com/api/removesubdomain/
        """
        self.zones.pop((domain, subdomain), None)
        return "OK"


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> List[float]:
    """
    Records sleeps of the plugin instead of sleeping.
    """
    calls: List[float] = []
    monkeypatch.setattr(certbot_dns_loopia, "sleep", calls.append)
    return calls


@pytest.fixture
def loopia(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeLoopia]:
    """
    Fake Loopia API that LoopiaClient talks to.
    """
    server = FakeLoopia()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr(LoopiaClient, "url", server.url)
    monkeypatch.setattr(LoopiaClient, "timeout", 0.5)
    yield server
    server.unstall.set()
    server.shutdown()
    server.server_close()


@pytest.fixture
def auth(tmp_path: Path) -> LoopiaAuthenticator:
    """
    Authenticator with a credentials file for the fake Loopia API.
    """
    credentials = tmp_path / "loopia.ini"
    credentials.write_text(f'dns_loopia_user = {USER}\ndns_loopia_password = "{PASSWORD}"\n')
    credentials.chmod(0o600)
    config = MagicMock(
        dns_loopia_credentials=str(credentials),
        dns_loopia_propagation_seconds=60,
    )
    authenticator = LoopiaAuthenticator(config, "dns-loopia")
    authenticator._setup_credentials()
    return authenticator


def test_perform_cleanup_cycle(loopia: FakeLoopia, auth: LoopiaAuthenticator) -> None:
    """
    Performs a full cycle including cleanup
    """
    auth._perform("*.example.se", "_acme-challenge.example.se", "token")

    assert loopia.zones == {
        ("example.se", "_acme-challenge"): [
            {"type": "TXT", "ttl": 30, "priority": 0, "rdata": "token", "record_id": 1},
        ],
    }

    auth._cleanup("*.example.se", "_acme-challenge.example.se", "token")

    assert not loopia.zones
    assert loopia.calls == [
        "addZoneRecord",
        "getZoneRecords",
        "removeZoneRecord",
        "removeSubdomain",
    ]


def test_cleanup_keeps_other_records(loopia: FakeLoopia, auth: LoopiaAuthenticator) -> None:
    """
    Records the plugin did not create stay, and so does their subdomain
    """
    loopia.zones["example.se", "_acme-challenge"] = [
        {"type": "TXT", "ttl": 3600, "priority": 0, "rdata": "other", "record_id": 99},
    ]
    auth._perform("example.se", "_acme-challenge.example.se", "token")
    auth._cleanup("example.se", "_acme-challenge.example.se", "token")

    assert [r["rdata"] for r in loopia.zones["example.se", "_acme-challenge"]] == ["other"]
    assert "removeSubdomain" not in loopia.calls


@pytest.mark.parametrize("name, expected", [
    ("_acme-challenge.example.se", ("example.se", "_acme-challenge")),
    ("_acme-challenge.www.example.se", ("example.se", "_acme-challenge.www")),
    ("_acme-challenge.example.co.uk", ("example.co.uk", "_acme-challenge")),
    ("_acme-challenge.example.pp.se", ("example.pp.se", "_acme-challenge")),
])
def test_split_domain(auth: LoopiaAuthenticator, name: str, expected: Tuple[str, str]) -> None:
    """
    Finds the Loopia domain from the bundled public suffix list
    """
    assert auth._split_domain(name) == expected


@pytest.mark.parametrize("method, args", [
    ("addZoneRecord", ("example.se", "x", {})),
    ("getZoneRecords", ("example.se", "x")),
])
def test_error_status(loopia: FakeLoopia, method: str, args: Tuple[Any, ...]) -> None:
    """
    Loopia returns errors as status strings instead of XML-RPC faults
    """
    with pytest.raises(PluginError, match="AUTH_ERROR"):
        LoopiaClient(USER, "wrong").call(method, *args)
    assert loopia.calls == [method]


def test_stalled_call_is_retried(loopia: FakeLoopia, sleeps: List[float]) -> None:
    """
    A hanging API call times out and is tried again
    """
    loopia.stalls = 1

    assert LoopiaClient(USER, PASSWORD).call("getZoneRecords", "example.se", "x") == []
    assert loopia.calls == ["getZoneRecords", "getZoneRecords"]
    assert len(sleeps) == 1


def test_unreachable_api(monkeypatch: pytest.MonkeyPatch, sleeps: List[float]) -> None:
    """
    Gives up after a few attempts without leaking the password
    """
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    monkeypatch.setattr(LoopiaClient, "url", f"http://127.0.0.1:{port}/RPCSERV")

    with pytest.raises(PluginError) as error:
        LoopiaClient(USER, PASSWORD).call("getZoneRecords", "example.se", "x")
    assert PASSWORD not in str(error.value)
    assert len(sleeps) == LoopiaClient.attempts - 1
