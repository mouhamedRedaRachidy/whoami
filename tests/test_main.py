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
}

SAMPLE_SCAN = {
    "target": "93.184.216.34",
    "target_type": "ip",
    "ips": ["93.184.216.34"],
    "skipped_ips": [],
    "hosts_truncated": False,
    "ports_scanned": 58,
    "timeout_seconds": 1.0,
    "checked_at": "2026-11-03T12:00:00+00:00",
    "duration_ms": 913.4,
    "hosts": [
        {
            "ip": "93.184.216.34",
            "open_count": 2,
            "duration_ms": 400.1,
            "open_ports": [
                {"port": 80, "service": "http", "latency_ms": 12.3},
                {"port": 443, "service": "https", "latency_ms": 15.7},
            ],
        }
    ],
}


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


def test_report_pdf(fake_audit):
    response = client.get("/report.pdf", params={"domain": "example.com"})

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert 'filename="domain-pulse-example.com.pdf"' in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF")
    assert len(response.content) > 1000


def test_pdf_handles_empty_report():
    content = main.build_pdf_report({"domain": "example.com"})

    assert content.startswith(b"%PDF")


def test_is_public_ip():
    assert main._is_public_ip("93.184.216.34") is True
    assert main._is_public_ip("127.0.0.1") is False
    assert main._is_public_ip("192.168.1.10") is False
    assert main._is_public_ip("pas-une-ip") is False


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


def test_parse_ports_default():
    assert main._parse_ports(None) == list(main.COMMON_PORTS)


def test_parse_ports_custom_and_ranges():
    assert main._parse_ports("22, 80,443, 8000-8002") == [
        22,
        80,
        443,
        8000,
        8001,
        8002,
    ]


@pytest.mark.parametrize("spec", ["0", "65536", "8000-7000", "abc", "22,abc"])
def test_parse_ports_rejects_invalid(spec):
    with pytest.raises(main.HTTPException) as excinfo:
        main._parse_ports(spec)

    assert excinfo.value.status_code == 422


def test_parse_ports_rejects_too_many():
    with pytest.raises(main.HTTPException):
        main._parse_ports("1-2048")


def test_scan_host_collects_open_ports(monkeypatch):
    async def fake_probe(ip, port, timeout):
        if port in (22, 80):
            return {
                "port": port,
                "service": main._service_name(port),
                "latency_ms": 1.5,
            }
        return None

    monkeypatch.setattr(main, "_probe_port", fake_probe)

    result = asyncio.run(main._scan_host("93.184.216.34", [22, 80, 443], 1.0))

    assert result["open_count"] == 2
    assert [item["port"] for item in result["open_ports"]] == [22, 80]


def test_scan_route(monkeypatch):
    async def fake_scan(target, ports, timeout, refresh=False):
        report = deepcopy(SAMPLE_SCAN)
        report["target"] = target
        return report

    monkeypatch.setattr(main, "get_scan", fake_scan)

    response = client.get(
        "/scan",
        params={"target": "93.184.216.34", "ports": "80,443"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["target"] == "93.184.216.34"
    assert data["hosts"][0]["open_ports"][0]["port"] == 80


def test_scan_rejects_private_ip():
    response = client.get("/scan", params={"target": "192.168.1.10"})

    assert response.status_code == 400
    assert "ALLOW_PRIVATE_SCAN" in response.json()["detail"]


def test_scan_rejects_invalid_ports():
    response = client.get(
        "/scan",
        params={"target": "93.184.216.34", "ports": "1-2048"},
    )

    assert response.status_code == 422


def test_scan_report_pdf(monkeypatch):
    async def fake_scan(target, ports, timeout, refresh=False):
        report = deepcopy(SAMPLE_SCAN)
        report["target"] = target
        return report

    monkeypatch.setattr(main, "get_scan", fake_scan)

    response = client.get(
        "/scan/report.pdf",
        params={"target": "93.184.216.34", "ports": "80,443"},
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert "domain-pulse-scan-93.184.216.34.pdf" in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF")


def test_scan_pdf_handles_empty_report():
    content = main.build_scan_pdf_report({"target": "1.2.3.4"})

    assert content.startswith(b"%PDF")
