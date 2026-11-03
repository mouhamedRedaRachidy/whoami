import asyncio
from copy import deepcopy

import httpx
import pytest
from fastapi.testclient import TestClient

import main
from main import app

client = TestClient(app)

SAMPLE_REPORT = {
    "domain": "example.com",
    "checked_at": "2026-11-03T12:00:00+00:00",
    "available": True,
    "reachable": True,
    "status_code": 200,
    "response_time_ms": 123.45,
    "ips": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"],
    "server": {
        "primary_ip": "93.184.216.34",
        "reverse_dns": ["server.example.net"],
        "http_header": "nginx/1.27",
    },
    "http": {
        "url": "https://example.com/",
        "available": True,
        "reachable": True,
        "status_code": 200,
        "status_ok": True,
        "response_time_ms": 123.45,
        "scheme": "https",
        "tls_verified": True,
        "server": "nginx/1.27",
        "headers": {"server": "nginx/1.27", "content-type": "text/html"},
        "redirected": False,
        "note": None,
    },
    "tls": {
        "subject": "example.com",
        "organization": "Example",
        "issuer": "DigiCert",
        "serial_number": "01",
        "not_before": "Oct  1 00:00:00 2026 GMT",
        "expires_at": "2027-01-01T00:00:00+00:00",
        "days_left": 58,
        "protocol": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "san": ["example.com", "www.example.com"],
        "verified": True,
    },
    "timings": {"dns_ms": 12.5, "http_ms": 123.45, "total_ms": 140.25},
    "dns": {
        "A": ["93.184.216.34"],
        "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
        "MX": ["10 mail.example.com"],
        "NS": ["a.iana-servers.net", "b.iana-servers.net"],
        "TXT": ["v=spf1 -all"],
        "DMARC": ["v=DMARC1; p=reject"],
    },
    "subdomains": ["example.com", "www.example.com"],
    "subdomains_total": 2,
    "subdomains_source": "certificat TLS + crt.sh",
    "ports": {
        "protocol": "TCP",
        "ports": list(main.SCAN_PORTS),
        "timeout_seconds": 2.0,
        "max_connections": 10,
        "max_ips": 4,
        "scanned_ips": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"],
        "not_scanned_ips": ["93.184.216.35"],
        "rejected_ips": ["10.0.0.1"],
        "hosts": [
            {
                "ip": "93.184.216.34",
                "version": 4,
                "open_ports": [
                    {"port": 80, "service": "HTTP", "latency_ms": 12.3, "state": "open"},
                    {"port": 443, "service": "HTTPS", "latency_ms": 15.7, "state": "open"},
                ],
                "open_count": 2,
                "refused_ports": [22],
                "timeout_ports": [3306],
                "error_ports": [{"port": 25, "error": "Network is unreachable"}],
                "duration_ms": 2001.0,
            }
        ],
        "skipped": False,
        "error": None,
        "notes": list(main.PORT_SCAN_NOTES),
        "duration_ms": 2010.0,
    },
}

@pytest.fixture(autouse=True)
def no_real_connections(monkeypatch):
    """Garde-fou : aucun test ne doit ouvrir une vraie connexion TCP."""

    async def forbidden(*args, **kwargs):
        raise AssertionError(f"Connexion réseau réelle interdite en test : {args}")

    monkeypatch.setattr(main.asyncio, "open_connection", forbidden)


@pytest.fixture(autouse=True)
def clear_cache():
    main._cache.clear()
    yield
    main._cache.clear()


@pytest.fixture
def fake_audit(monkeypatch):
    calls = []

    async def audit(domain: str):
        calls.append(domain)
        report = deepcopy(SAMPLE_REPORT)
        report["domain"] = domain
        return report

    monkeypatch.setattr(main, "audit_domain", audit)
    return calls


def test_home():
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Domain Pulse" in response.text


def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_check_returns_full_audit(fake_audit):
    response = client.get("/check", params={"domain": "Example.COM"})

    assert response.status_code == 200
    data = response.json()

    assert data["domain"] == "example.com"
    assert data["ips"] == SAMPLE_REPORT["ips"]
    assert data["server"]["reverse_dns"] == ["server.example.net"]
    assert data["timings"]["total_ms"] == 140.25
    assert data["dns"]["MX"] == ["10 mail.example.com"]
    assert "www.example.com" in data["subdomains"]


def test_check_is_cached(fake_audit):
    client.get("/check", params={"domain": "example.com"})
    client.get("/check", params={"domain": "example.com"})

    assert fake_audit == ["example.com"]


def test_check_refresh_bypasses_cache(fake_audit):
    client.get("/check", params={"domain": "example.com"})
    client.get("/check", params={"domain": "example.com", "refresh": "true"})

    assert fake_audit == ["example.com", "example.com"]


def test_check_rejects_ip_literal():
    response = client.get("/check", params={"domain": "127.0.0.1"})

    assert response.status_code == 400
    assert "adresses IP" in response.json()["detail"]


def test_check_rejects_invalid_domain():
    response = client.get("/check", params={"domain": "localhost"})

    assert response.status_code == 422


def test_report_pdf_reuses_analysis_without_rescanning(fake_audit):
    client.get("/check", params={"domain": "example.com"})
    response = client.get("/report.pdf", params={"domain": "example.com"})

    assert fake_audit == ["example.com"]

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert 'filename="domain-pulse-example.com.pdf"' in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF")
    assert len(response.content) > 1000


def test_report_pdf_without_analysis_does_not_scan(fake_audit):
    response = client.get("/report.pdf", params={"domain": "example.com"})

    assert response.status_code == 404
    assert "Analyser" in response.json()["detail"]
    assert fake_audit == []


def test_report_pdf_still_available_after_check_cache_expires(fake_audit, monkeypatch):
    client.get("/check", params={"domain": "example.com"})
    created, report = main._cache["example.com"]
    main._cache["example.com"] = (created - main.CACHE_TTL_SECONDS - 1, report)

    response = client.get("/report.pdf", params={"domain": "example.com"})

    assert response.status_code == 200
    assert fake_audit == ["example.com"]


def test_pdf_contains_port_section(monkeypatch):
    rows = []
    original = main._pdf_row

    def spy(pdf, label, value, label_width=48):
        rows.append((label, str(value)))
        original(pdf, label, value, label_width)

    monkeypatch.setattr(main, "_pdf_row", spy)

    content = main.build_pdf_report(deepcopy(SAMPLE_REPORT))
    labels = dict(rows)

    assert content.startswith(b"%PDF")
    assert labels["Port 80 ouvert"].startswith("HTTP (indicatif)")
    assert "12.30 ms" in labels["Port 80 ouvert"]
    assert labels["Connexion refusée"] == "22"
    assert labels["Délai dépassé"] == "3306"
    assert "93.184.216.35" in labels["IP non testées"]
    assert "10.0.0.1" in labels["IP refusées"]


def test_pdf_handles_empty_report():
    content = main.build_pdf_report({"domain": "example.com"})

    assert content.startswith(b"%PDF")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("93.184.216.34", True),
        ("2606:2800:220:1:248:1893:25c8:1946", True),
        ("127.0.0.1", False),
        ("192.168.1.10", False),
        ("10.0.0.1", False),
        ("172.16.0.1", False),
        ("169.254.169.254", False),  # métadonnées cloud
        ("100.64.0.1", False),  # CGNAT
        ("0.0.0.0", False),
        ("240.0.0.1", False),  # réservé
        ("239.1.1.1", False),  # multicast
        ("::1", False),
        ("fe80::1", False),
        ("fd00::1", False),
        ("::ffff:10.0.0.1", False),  # IPv4 privée encapsulée
        ("pas-une-ip", False),
    ],
)
def test_is_public_ip(value, expected):
    assert main._is_public_ip(value) is expected


@pytest.mark.parametrize("domain", ["localhost", "printer.local", "api.internal"])
def test_normalize_rejects_private_hostnames(domain):
    with pytest.raises(main.HTTPException):
        main._normalize_domain(domain)


def test_normalize_strips_trailing_dot():
    assert main._normalize_domain("EXAMPLE.com.") == "example.com"


def test_audit_skips_tls_for_private_ips(monkeypatch):
    async def fake_dns(domain):
        return {"A": ["192.168.1.10"]}, 1.0

    async def fake_empty_set(domain):
        return set()

    async def fake_reverse(ips):
        return []

    async def fake_http(domain, ips):
        return {
            "url": f"https://{domain}",
            "available": False,
            "status_code": None,
            "response_time_ms": None,
            "skipped": True,
            "error": "Adresse IP non publique : requête bloquée par sécurité.",
        }

    fetched = []

    def fake_certificate(host):
        fetched.append(host)
        return {}

    monkeypatch.setattr(main, "_resolve_dns", fake_dns)
    monkeypatch.setattr(main, "_crt_sh_subdomains", fake_empty_set)
    monkeypatch.setattr(main, "_probe_subdomains", fake_empty_set)
    monkeypatch.setattr(main, "_reverse_dns_many", fake_reverse)
    monkeypatch.setattr(main, "_http_check", fake_http)
    monkeypatch.setattr(main, "_fetch_certificate", fake_certificate)

    report = asyncio.run(main.audit_domain("example.com"))

    assert fetched == []
    assert report["ports"]["skipped"] is True
    assert report["ports"]["rejected_ips"] == ["192.168.1.10"]
    assert report["ports"]["hosts"] == []
    assert report["tls"]["error"].startswith("Aucune adresse IP publique")
    assert report["subdomains"] == []


class FakeResponse:
    def __init__(self, status_code, url, headers=None, history=()):
        self.status_code = status_code
        self.url = url
        self.headers = headers or {}
        self.history = list(history)


def _connect_error(url, message):
    return httpx.ConnectError(message, request=httpx.Request("GET", url))


def test_http_check_falls_back_to_http(monkeypatch):
    async def fake_attempt(url, verify, timeout):
        if url.startswith("https://"):
            raise _connect_error(url, "SSL: CERTIFICATE_VERIFY_FAILED")
        return FakeResponse(200, "http://example.com/", {"server": "nginx"}), 42.0

    monkeypatch.setattr(main, "_http_attempt", fake_attempt)

    result = asyncio.run(main._http_check("example.com", ["93.184.216.34"]))

    assert result["reachable"] is True
    assert result["available"] is True
    assert result["status_code"] == 200
    assert result["scheme"] == "http"
    assert result["note"] == "Réponse obtenue en HTTP : HTTPS indisponible ou en erreur."
    assert len(result["attempts"]) == 2


def test_http_check_accepts_invalid_certificate(monkeypatch):
    async def fake_attempt(url, verify, timeout):
        if verify:
            raise _connect_error(url, "certificate verify failed")
        return FakeResponse(200, "https://example.com/"), 25.0

    monkeypatch.setattr(main, "_http_attempt", fake_attempt)

    result = asyncio.run(main._http_check("example.com", ["93.184.216.34"]))

    assert result["scheme"] == "https"
    assert result["tls_verified"] is False
    assert result["available"] is True
    assert "Certificat TLS non valide" in result["note"]


@pytest.mark.parametrize(("status", "available"), [(403, True), (503, False)])
def test_http_check_reports_reachability(status, available, monkeypatch):
    async def fake_attempt(url, verify, timeout):
        return FakeResponse(status, "https://example.com/"), 10.0

    monkeypatch.setattr(main, "_http_attempt", fake_attempt)

    result = asyncio.run(main._http_check("example.com", ["93.184.216.34"]))

    assert result["reachable"] is True
    assert result["available"] is available
    assert result["status_code"] == status


# ---------------------------------------------------------------------------
# Ports TCP : connexions simulées uniquement
# ---------------------------------------------------------------------------


class FakeWriter:
    def __init__(self):
        self.closed = False
        self.waited = False
        self.transport = self

    def close(self):
        self.closed = True

    async def wait_closed(self):
        self.waited = True

    def abort(self):
        self.closed = True


def _probe(port=443, timeout=2.0):
    return asyncio.run(
        main._probe_port("93.184.216.34", port, timeout, asyncio.Semaphore(10))
    )


def test_probe_port_open_closes_connection(monkeypatch):
    writer = FakeWriter()

    async def fake_open(host, port):
        return object(), writer

    monkeypatch.setattr(main.asyncio, "open_connection", fake_open)

    result = _probe(443)

    assert result["state"] == "open"
    assert result["service"] == "HTTPS"
    assert isinstance(result["latency_ms"], float)
    assert writer.closed and writer.waited


def test_probe_port_refused(monkeypatch):
    async def fake_open(host, port):
        raise ConnectionRefusedError(61, "Connection refused")

    monkeypatch.setattr(main.asyncio, "open_connection", fake_open)

    result = _probe(22)

    assert result["state"] == "refused"
    assert result["service"] == "SSH"
    assert result["latency_ms"] is None


def test_probe_port_timeout(monkeypatch):
    cancelled = []

    async def fake_open(host, port):
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            cancelled.append(port)
            raise

    monkeypatch.setattr(main.asyncio, "open_connection", fake_open)

    result = _probe(3306, timeout=0.01)

    assert result["state"] == "timeout"
    assert cancelled == [3306]


def test_probe_port_other_network_error(monkeypatch):
    async def fake_open(host, port):
        raise OSError(51, "Network is unreachable")

    monkeypatch.setattr(main.asyncio, "open_connection", fake_open)

    result = _probe(53)

    assert result["state"] == "error"
    assert result["error"] == "Network is unreachable"


def test_scan_ports_classifies_each_state(monkeypatch):
    async def fake_open(host, port):
        if port in (80, 443):
            return object(), FakeWriter()
        if port == 22:
            raise ConnectionRefusedError
        await asyncio.sleep(60)

    monkeypatch.setattr(main.asyncio, "open_connection", fake_open)
    monkeypatch.setattr(main, "PORT_SCAN_TIMEOUT_SECONDS", 0.01)

    result = asyncio.run(main.scan_ports(["93.184.216.34"]))
    host = result["hosts"][0]

    assert result["protocol"] == "TCP"
    assert result["scanned_ips"] == ["93.184.216.34"]
    assert [item["port"] for item in host["open_ports"]] == [80, 443]
    assert host["refused_ports"] == [22]
    assert set(host["timeout_ports"]) == set(main.SCAN_PORTS) - {22, 80, 443}
    assert host["version"] == 4


def test_scan_ports_never_exceeds_ten_connections(monkeypatch):
    active = 0
    peak = 0
    calls = []

    async def fake_open(host, port):
        nonlocal active, peak
        calls.append((host, port))
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.005)
        active -= 1
        raise ConnectionRefusedError

    monkeypatch.setattr(main.asyncio, "open_connection", fake_open)

    ips = ["93.184.216.34", "93.184.216.35", "2606:2800::1", "2606:2800::2"]
    asyncio.run(main.scan_ports(ips))

    assert len(calls) == 4 * len(main.SCAN_PORTS)
    assert 1 < peak <= main.PORT_SCAN_MAX_CONNECTIONS


def test_scan_ports_limits_ips_and_rejects_private(monkeypatch):
    called_hosts = set()

    async def fake_open(host, port):
        called_hosts.add(host)
        raise ConnectionRefusedError

    monkeypatch.setattr(main.asyncio, "open_connection", fake_open)

    ips = [
        "93.184.216.1",
        "93.184.216.2",
        "93.184.216.3",
        "93.184.216.4",
        "10.0.0.1",
        "2606:2800::1",
        "127.0.0.1",
    ]
    result = asyncio.run(main.scan_ports(ips))

    # IPv4 et IPv6 alternées, 4 IP maximum.
    assert result["scanned_ips"] == [
        "93.184.216.1",
        "2606:2800::1",
        "93.184.216.2",
        "93.184.216.3",
    ]
    assert result["not_scanned_ips"] == ["93.184.216.4"]
    assert result["rejected_ips"] == ["10.0.0.1", "127.0.0.1"]
    assert called_hosts == set(result["scanned_ips"])


def test_scan_ports_without_public_ip_makes_no_connection():
    # Le garde-fou autouse ferait échouer le test en cas de connexion.
    result = asyncio.run(main.scan_ports(["192.168.1.10", "::1"]))

    assert result["skipped"] is True
    assert "Aucune adresse IP publique" in result["error"]
    assert result["hosts"] == []


def test_scan_ports_without_any_ip():
    result = asyncio.run(main.scan_ports([]))

    assert result["skipped"] is True
    assert "Aucune adresse IP trouvée" in result["error"]


def test_scan_notes_mention_tcp_udp_and_cdn():
    notes = " ".join(main.PORT_SCAN_NOTES)

    assert "UDP" in notes
    assert "CDN" in notes
    assert "autorisé" in notes


def test_fixed_port_list():
    assert main.SCAN_PORTS == (
        21, 22, 25, 53, 80, 110, 143, 443, 465, 587,
        993, 995, 3306, 5432, 6379, 8000, 8080, 8443,
    )


@pytest.mark.parametrize("path", ["/scan", "/scan/report.pdf"])
def test_free_form_scan_routes_are_gone(path):
    response = client.get(path, params={"target": "1.1.1.1", "ports": "1-1024"})

    assert response.status_code == 404


def test_home_has_no_ip_or_port_fields():
    html = client.get("/").text

    assert 'id="domain"' in html
    assert "scan-target" not in html
    assert "scan-ports" not in html
    assert "Analyser" in html


def test_resolve_dns_uses_system_fallback(monkeypatch):
    async def fake_resolve_type(resolver, name, rdtype, fallback=None):
        return []

    async def fake_system_addresses(domain):
        return [
            "93.184.216.34",
            "2606:2800:220:1:248:1893:25c8:1946",
        ]

    monkeypatch.setattr(main, "_resolve_type", fake_resolve_type)
    monkeypatch.setattr(main, "_system_addresses", fake_system_addresses)

    records, _ = asyncio.run(main._resolve_dns("example.com"))

    assert records["A"] == ["93.184.216.34"]
    assert records["AAAA"] == ["2606:2800:220:1:248:1893:25c8:1946"]
