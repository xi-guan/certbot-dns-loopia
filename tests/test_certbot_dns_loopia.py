"""
Tests for certbot-dns-loopia
"""
# pylint: disable=protected-access,redefined-outer-name,invalid-name,too-many-instance-attributes
import itertools
import logging
import socket
import threading
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple
from unittest.mock import MagicMock, patch
from xmlrpc.server import SimpleXMLRPCServer

import dns.flags
import dns.message
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest
from acme import challenges, messages
from certbot import achallenges
from certbot.errors import PluginError
from certbot.tests import acme_util
from cryptography.hazmat.primitives.asymmetric import rsa
from josepy.jwk import JWKRSA

import certbot_dns_loopia
from certbot_dns_loopia import LoopiaAuthenticator, LoopiaClient

USER = "test@loopiaapi"
# quoted in the INI file, otherwise configobj cuts the value at "#" (issue #42)
PASSWORD = "pass#word"
ACCOUNT_KEY = JWKRSA(key=rsa.generate_private_key(public_exponent=65537, key_size=2048))


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


class FakeClock:
    """
    Time of the plugin, which moves only when the plugin sleeps.
    """

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: List[float] = []

    def monotonic(self) -> float:
        """
        Replaces time.monotonic
        """
        return self.now

    def sleep(self, seconds: float) -> None:
        """
        Replaces time.sleep
        """
        self.sleeps.append(seconds)
        self.now += seconds


class FakeDns(threading.Thread):
    """
    DNS server on localhost for example.se, serving the TXT records of the fake
    Loopia API once the clock reaches `delay`.
    """

    def __init__(self, loopia: FakeLoopia, clock: FakeClock) -> None:
        super().__init__(daemon=True)
        self.loopia = loopia
        self.clock = clock
        self.delay = 0.0
        #: Extra delay for each further record on the same name
        self.stagger = 0.0
        #: Ignore TXT queries, like a firewall blocking port 53
        self.drop_txt = False
        self.records: Dict[Tuple[str, str], List[str]] = {
            ("example.se.", "NS"): ["ns1.example.se."],
            ("ns1.example.se.", "A"): ["127.0.0.1"],
        }
        #: (name, type, recursion desired) of each query
        self.queries: List[Tuple[str, str, bool]] = []
        self.stopped = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.port: int = self.sock.getsockname()[1]

    def run(self) -> None:
        while not self.stopped.is_set():
            try:
                data, peer = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            response = self.answer(dns.message.from_wire(data))
            if response is not None:
                self.sock.sendto(response.to_wire(), peer)
        self.sock.close()

    def answer(self, query: dns.message.Message) -> Optional[dns.message.Message]:
        """
        Response to a query, empty if the name or type is unknown, None if dropped.
        """
        question = query.question[0]
        key = (question.name.to_text(), dns.rdatatype.to_text(question.rdtype))
        self.queries.append(key + (bool(query.flags & dns.flags.RD),))
        if self.drop_txt and key[1] == "TXT":
            return None

        values = list(self.records.get(key, []))
        if key[1] == "TXT":
            for (domain, subdomain), records in list(self.loopia.zones.items()):
                if key[0] == f"{subdomain}.{domain}.":
                    values += [
                        f'"{record["rdata"]}"'
                        for i, record in enumerate(records)
                        if self.clock.now >= self.delay + i * self.stagger
                    ]

        response = dns.message.make_response(query)
        if values:
            response.answer.append(
                dns.rrset.from_text_list(question.name, 30, "IN", key[1], values),
            )
        return response


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> FakeClock:
    """
    Fake time for the plugin, so tests do not really sleep.
    """
    fake = FakeClock()
    monkeypatch.setattr(certbot_dns_loopia, "monotonic", fake.monotonic)
    monkeypatch.setattr(certbot_dns_loopia, "sleep", fake.sleep)
    return fake


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
def dns_server(
        monkeypatch: pytest.MonkeyPatch,
        loopia: FakeLoopia,
        clock: FakeClock,
) -> Iterator[FakeDns]:
    """
    Fake DNS used both as resolver and as authoritative nameserver.
    """
    server = FakeDns(loopia, clock)
    server.start()
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = server.port
    monkeypatch.setattr(dns.resolver, "default_resolver", resolver)
    monkeypatch.setattr(LoopiaAuthenticator, "dns_port", server.port)
    monkeypatch.setattr(LoopiaAuthenticator, "dns_timeout", 0.5)
    yield server
    server.stopped.set()
    server.join()


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


def test_cleanup_keeps_other_records(
        loopia: FakeLoopia,
        auth: LoopiaAuthenticator,
        caplog: pytest.LogCaptureFixture,
) -> None:
    """
    Records the plugin did not create stay, and so does their subdomain
    """
    caplog.set_level(logging.DEBUG)
    loopia.zones["example.se", "_acme-challenge"] = [
        {"type": "TXT", "ttl": 3600, "priority": 0, "rdata": "other", "record_id": 99},
    ]
    auth._perform("example.se", "_acme-challenge.example.se", "token")
    auth._cleanup("example.se", "_acme-challenge.example.se", "token")

    assert [r["rdata"] for r in loopia.zones["example.se", "_acme-challenge"]] == ["other"]
    assert "removeSubdomain" not in loopia.calls
    assert "'rdata': 'other'" in caplog.text


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


def test_stalled_call_is_retried(loopia: FakeLoopia, clock: FakeClock) -> None:
    """
    A hanging API call times out and is tried again
    """
    loopia.stalls = 1

    assert LoopiaClient(USER, PASSWORD).call("getZoneRecords", "example.se", "x") == []
    assert loopia.calls == ["getZoneRecords", "getZoneRecords"]
    assert len(clock.sleeps) == 1


def test_unreachable_api(monkeypatch: pytest.MonkeyPatch, clock: FakeClock) -> None:
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
    assert len(clock.sleeps) == LoopiaClient.attempts - 1


def perform(auth: LoopiaAuthenticator, *domains: str) -> List[achallenges.AnnotatedChallenge]:
    """
    Runs certbot's perform for one challenge per domain, example.se by default.
    """
    achalls: List[achallenges.AnnotatedChallenge] = [
        achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.DNS01(token=bytes([i]) * 16), messages.STATUS_PENDING,
            ),
            identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=domain),
            account_key=ACCOUNT_KEY,
        )
        for i, domain in enumerate(domains or ("example.se",))
    ]
    with patch("certbot.display.util.notify"):
        assert len(auth.perform(achalls)) == len(achalls)
    return achalls


def test_visible_immediately(
        dns_server: FakeDns,
        auth: LoopiaAuthenticator,
        clock: FakeClock,
) -> None:
    """
    Continues without waiting when the nameserver already has the record
    """
    perform(auth)

    assert clock.now == 0
    txt_queries = [q for q in dns_server.queries if q[1] == "TXT"]
    assert txt_queries == [("_acme-challenge.example.se.", "TXT", False)]


def test_visible_after_a_while(
        dns_server: FakeDns,
        auth: LoopiaAuthenticator,
        clock: FakeClock,
) -> None:
    """
    Polls until the nameserver has the record
    """
    dns_server.delay = 12

    perform(auth)

    assert clock.sleeps == [5, 5, 5]


def test_never_visible(
        dns_server: FakeDns,
        auth: LoopiaAuthenticator,
        clock: FakeClock,
        caplog: pytest.LogCaptureFixture,
) -> None:
    """
    Gives up at propagation-seconds and lets the CA try anyway
    """
    dns_server.delay = float("inf")

    perform(auth)

    assert clock.now == 60
    assert "still not visible on nameservers 127.0.0.1" in caplog.text


def test_silent_nameserver(
        monkeypatch: pytest.MonkeyPatch,
        dns_server: FakeDns,
        auth: LoopiaAuthenticator,
        clock: FakeClock,
        caplog: pytest.LogCaptureFixture,
) -> None:
    """
    Keeps asking an IPv4 nameserver that never answers until propagation-seconds
    """
    monkeypatch.setattr(LoopiaAuthenticator, "dns_timeout", 0.1)
    dns_server.drop_txt = True

    perform(auth)

    assert clock.now == 60
    assert len([q for q in dns_server.queries if q[1] == "TXT"]) == 13
    assert "still not visible on nameservers 127.0.0.1" in caplog.text


def test_wildcard_and_base_domain(
        dns_server: FakeDns,
        loopia: FakeLoopia,
        auth: LoopiaAuthenticator,
        clock: FakeClock,
) -> None:
    """
    example.se and *.example.se put two values on _acme-challenge.example.se,
    which may show up at different times
    """
    dns_server.delay = 6
    dns_server.stagger = 6

    # the ACME server names the wildcard authorization example.se as well
    achalls = perform(auth, "example.se", "example.se")

    assert clock.sleeps == [5, 5, 5]
    assert len(loopia.zones["example.se", "_acme-challenge"]) == 2

    auth.cleanup(achalls)

    assert not loopia.zones
    assert loopia.calls.count("removeZoneRecord") == 2
    assert loopia.calls.count("removeSubdomain") == 1


def test_two_loopia_domains(
        dns_server: FakeDns,
        auth: LoopiaAuthenticator,
        clock: FakeClock,
) -> None:
    """
    Each domain is checked on its own nameservers
    """
    dns_server.records["other.se.", "NS"] = ["ns1.example.se."]

    perform(auth, "example.se", "other.se")

    assert clock.now == 0
    queries = {q[:2] for q in dns_server.queries}
    assert {("example.se.", "NS"), ("other.se.", "NS")} <= queries
    assert {
        ("_acme-challenge.example.se.", "TXT"),
        ("_acme-challenge.other.se.", "TXT"),
    } <= queries


def test_unreachable_ipv6_is_ignored(
        dns_server: FakeDns,
        auth: LoopiaAuthenticator,
        clock: FakeClock,
        caplog: pytest.LogCaptureFixture,
) -> None:
    """
    An IPv6 nameserver address without a route does not block
    """
    caplog.set_level(logging.DEBUG)
    # documentation prefix, never routable
    dns_server.records["ns1.example.se.", "AAAA"] = ["2001:db8::1"]

    perform(auth)

    assert clock.now == 0
    assert "Nameserver 2001:db8::1 did not answer" in caplog.text


def test_nameserver_lookup_fails(
        dns_server: FakeDns,
        auth: LoopiaAuthenticator,
        clock: FakeClock,
        caplog: pytest.LogCaptureFixture,
) -> None:
    """
    Falls back to waiting the full propagation-seconds
    """
    del dns_server.records["example.se.", "NS"]

    perform(auth)

    assert clock.now == 60
    assert "Could not look up the nameservers" in caplog.text
