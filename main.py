"""Domain Pulse - audit complet d'un nom de domaine.

Expose :
- ``/``          : interface web
- ``/health``    : sonde de disponibilité
- ``/check``     : audit JSON (DNS, IP, serveur, TLS, temps, sous-domaines)
- ``/report.pdf``: même audit au format PDF
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import ssl
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic, perf_counter
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename
import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates
from fpdf import FPDF
from fpdf.enums import XPos, YPos

app = FastAPI(title="Domain Pulse", version="1.0.0")

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

DOMAIN_PATTERN = (
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+$"
)

DOMAIN_QUERY = Query(
    ...,
    pattern=DOMAIN_PATTERN,
    max_length=253,
    description="Nom de domaine sans schéma, par exemple example.com",
)

DNS_RECORD_TYPES = (
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
    "SOA",
    "CAA",
    "SRV",
    "HTTPS",
)

COMMON_SUBDOMAINS = (
    "www",
    "api",
    "app",
    "admin",
    "mail",
    "webmail",
    "smtp",
    "imap",
    "vpn",
    "cdn",
    "static",
    "media",
    "blog",
    "docs",
    "shop",
    "store",
    "support",
    "status",
    "dev",
    "staging",
    "test",
    "portal",
    "dashboard",
    "auth",
)

MAX_SUBDOMAINS = 300
CACHE_TTL_SECONDS = 300
HTTP_TIMEOUT_SECONDS = 10
TLS_TIMEOUT_SECONDS = 8
CRTSH_TIMEOUT_SECONDS = 6
DNS_TIMEOUT_SECONDS = 2.5
DNS_RESOLVERS = [
    server.strip()
    for server in os.getenv(
        "DNS_RESOLVERS", "1.1.1.1,8.8.8.8,9.9.9.9"
    ).split(",")
    if server.strip()
]
USER_AGENT = "DomainPulse/1.0"

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36 DomainPulse/1.0"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr,en;q=0.8",
}

# Scan de ports
MAX_SCAN_PORTS = 1024
MAX_SCAN_HOSTS = 4
MAX_PARALLEL_SCANS = 128
DEFAULT_SCAN_TIMEOUT = 1.0
ALLOW_PRIVATE_SCAN = os.getenv("ALLOW_PRIVATE_SCAN", "").lower() in {
    "1",
    "true",
    "yes",
    "on",
}

COMMON_PORTS = (
    21,      # FTP
    22,      # SSH
    23,      # Telnet
    25,      # SMTP
    53,      # DNS
    80,      # HTTP
    110,     # POP3
    111,     # RPC
    135,     # MS RPC
    139,     # NetBIOS
    143,     # IMAP
    389,     # LDAP
    443,     # HTTPS
    445,     # SMB
    465,     # SMTPS
    587,     # SMTP submission
    631,     # IPP
    993,     # IMAPS
    995,     # POP3S
    1080,    # SOCKS
    1194,    # OpenVPN
    1433,    # MSSQL
    1521,    # Oracle
    1723,    # PPTP
    2049,    # NFS
    2082,    # cPanel
    2083,    # cPanel SSL
    2181,    # ZooKeeper
    2375,    # Docker
    2376,    # Docker TLS
    2379,    # etcd
    3000,    # Node / Grafana
    3306,    # MySQL
    3389,    # RDP
    4000,    # Dev
    5000,    # Dev
    5060,    # SIP
    5061,    # SIP TLS
    5432,    # PostgreSQL
    5601,    # Kibana
    5672,    # RabbitMQ
    5900,    # VNC
    6379,    # Redis
    6443,    # Kubernetes API
    7001,    # WebLogic
    8000,    # HTTP alternatif
    8008,    # HTTP alternatif
    8080,    # HTTP alternatif
    8081,    # HTTP alternatif
    8443,    # HTTPS alternatif
    8888,    # HTTP alternatif
    9000,    # Portainer / PHP-FPM
    9090,    # Prometheus
    9200,    # Elasticsearch
    9300,    # Elasticsearch
    10250,   # Kubelet
    11211,   # Memcached
    27017,   # MongoDB
)

_cache: dict[str, tuple[float, dict[str, Any]]] = {}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _normalize_domain(domain: str) -> str:
    """Nettoie et refuse les cibles qui ne sont pas des domaines publics."""
    value = domain.strip().lower().rstrip(".")

    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise HTTPException(
            status_code=400,
            detail="Les adresses IP ne sont pas acceptées. Utilisez un nom de domaine.",
        )

    if value == "localhost" or value.endswith((".local", ".internal", ".localhost")):
        raise HTTPException(
            status_code=400,
            detail="Ce nom d'hôte n'est pas un domaine public.",
        )

    return value


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def _new_resolver(use_public: bool = True) -> dns.asyncresolver.Resolver:
    """Résolveur public (cohérent) avec repli sur la configuration système."""
    nameservers = DNS_RESOLVERS if use_public else None
    resolver = dns.asyncresolver.Resolver(configure=not nameservers)

    if nameservers:
        resolver.nameservers = nameservers

    resolver.lifetime = DNS_TIMEOUT_SECONDS
    resolver.timeout = DNS_TIMEOUT_SECONDS
    resolver.retry_servfail = False
    return resolver


def _format_rdata(rdtype: str, rdata: Any) -> str:
    if rdtype == "MX":
        exchange = str(rdata.exchange).rstrip(".") or "."
        return f"{rdata.preference} {exchange}"
    if rdtype == "SRV":
        target = str(rdata.target).rstrip(".") or "."
        return f"{rdata.priority} {rdata.weight} {rdata.port} {target}"
    if rdtype == "SOA":
        return (
            f"{str(rdata.mname).rstrip('.')} {str(rdata.rname).rstrip('.')} "
            f"serial={rdata.serial} refresh={rdata.refresh} retry={rdata.retry} "
            f"expire={rdata.expire} minimum={rdata.minimum}"
        )
    if rdtype == "CAA":
        tag = (
            rdata.tag.decode(errors="replace")
            if isinstance(rdata.tag, bytes)
            else rdata.tag
        )
        value = (
            rdata.value.decode(errors="replace")
            if isinstance(rdata.value, bytes)
            else rdata.value
        )
        return f"{rdata.flags} {tag} {value}"
    if rdtype == "TXT":
        return "".join(part.decode("utf-8", "replace") for part in rdata.strings)
    return str(rdata).rstrip(".")


async def _resolve_type(
    resolver: dns.asyncresolver.Resolver,
    name: str,
    rdtype: str,
    fallback: dns.asyncresolver.Resolver | None = None,
) -> list[str]:
    try:
        answer = await resolver.resolve(name, rdtype, raise_on_no_answer=False)
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        if fallback is None:
            return []
        try:
            answer = await fallback.resolve(
                name, rdtype, raise_on_no_answer=False
            )
        except (dns.exception.DNSException, OSError):
            return []
    except (dns.exception.DNSException, OSError):
        return []

    if answer.rrset is None:
        return []

    return [_format_rdata(rdtype, rdata) for rdata in answer.rrset]


async def _system_addresses(domain: str) -> list[str]:
    """Dernier recours : résolution via la pile système (getaddrinfo)."""
    try:
        infos = await asyncio.to_thread(
            socket.getaddrinfo,
            domain,
            None,
            0,
            socket.SOCK_STREAM,
        )
    except OSError:
        return []

    return list(dict.fromkeys(info[4][0] for info in infos))


async def _resolve_dns(domain: str) -> tuple[dict[str, list[str]], float]:
    resolver = _new_resolver()
    fallback = _new_resolver(use_public=False)
    started = perf_counter()

    results = await asyncio.gather(
        *(
            _resolve_type(resolver, domain, rdtype, fallback)
            for rdtype in DNS_RECORD_TYPES
        )
    )
    records = {
        rdtype: values
        for rdtype, values in zip(DNS_RECORD_TYPES, results)
        if values
    }

    if not records.get("A") and not records.get("AAAA"):
        addresses = await _system_addresses(domain)
        ipv4 = [address for address in addresses if ":" not in address]
        ipv6 = [address for address in addresses if ":" in address]
        if ipv4:
            records["A"] = ipv4
        if ipv6:
            records["AAAA"] = ipv6

    dmarc = await _resolve_type(
        resolver, f"_dmarc.{domain}", "TXT", fallback
    )
    if dmarc:
        records["DMARC"] = dmarc

    return records, (perf_counter() - started) * 1000


async def _reverse_dns(ip: str) -> list[str]:
    resolver = _new_resolver()
    try:
        answer = await resolver.resolve(
            dns.reversename.from_address(ip), "PTR", lifetime=3
        )
    except (dns.exception.DNSException, OSError, ValueError):
        return []

    return [str(rdata).rstrip(".") for rdata in answer]


async def _reverse_dns_many(ips: list[str]) -> list[str]:
    results = await asyncio.gather(*(_reverse_dns(ip) for ip in ips))
    names: list[str] = []
    for item in results:
        names.extend(item)
    return list(dict.fromkeys(names))


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------


def _name_dict(items: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items or ():
        for key, value in item:
            result[key] = value
    return result


def _parse_certificate(
    cert: dict[str, Any],
    protocol: str | None,
    cipher: Any,
    verified: bool = True,
) -> dict[str, Any]:
    subject = _name_dict(cert.get("subject"))
    issuer = _name_dict(cert.get("issuer"))
    san = sorted(
        {
            name
            for kind, name in cert.get("subjectAltName", ())
            if kind == "DNS"
        }
    )

    expires_at: datetime | None = None
    days_left: int | None = None
    not_after = cert.get("notAfter")
    if not_after:
        try:
            expires_at = datetime.strptime(
                not_after, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=UTC)
            days_left = (expires_at - datetime.now(UTC)).days
        except ValueError:
            pass

    return {
        "subject": subject.get("commonName"),
        "organization": subject.get("organizationName"),
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "serial_number": cert.get("serialNumber"),
        "not_before": cert.get("notBefore"),
        "expires_at": expires_at.isoformat() if expires_at else not_after,
        "days_left": days_left,
        "protocol": protocol,
        "cipher": cipher[0] if cipher else None,
        "san": san,
        "verified": verified,
    }


def _fetch_certificate(host: str) -> dict[str, Any]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection(
            (host, 443), timeout=TLS_TIMEOUT_SECONDS
        ) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                protocol = tls.version()
                cipher = tls.cipher()
    except ssl.SSLCertVerificationError as exc:
        return {
            "error": f"Certificat non valide : {exc}",
            "verified": False,
        }
    except (OSError, ssl.SSLError) as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "verified": None}

    return _parse_certificate(cert, protocol, cipher)


async def _skipped_tls() -> dict[str, Any]:
    return {
        "error": "Aucune adresse IP publique : analyse TLS ignorée pour sécurité.",
        "verified": None,
    }


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


def _looks_like_tls_error(exc: httpx.RequestError) -> bool:
    message = str(exc).lower()
    return any(token in message for token in ("certificate", "ssl", "tls"))


async def _http_attempt(
    url: str,
    verify: bool,
    timeout: float,
) -> tuple[httpx.Response, float]:
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, connect=min(timeout, 5.0)),
        follow_redirects=True,
        headers=BROWSER_HEADERS,
        verify=verify,
    ) as client:
        started = perf_counter()
        response = await client.get(url)
        return response, (perf_counter() - started) * 1000


def _http_summary(
    response: httpx.Response,
    duration_ms: float,
    scheme: str,
    tls_verified: bool | None,
    attempts: list[dict[str, str]],
) -> dict[str, Any]:
    headers = {
        key: response.headers[key]
        for key in (
            "server",
            "content-type",
            "location",
            "x-powered-by",
            "via",
            "strict-transport-security",
        )
        if key in response.headers
    }

    note = None
    if scheme == "http":
        note = "Réponse obtenue en HTTP : HTTPS indisponible ou en erreur."
    elif tls_verified is False:
        note = "Certificat TLS non valide : réponse obtenue sans vérification."

    return {
        "url": str(response.url),
        "available": response.status_code < 500,
        "reachable": True,
        "status_code": response.status_code,
        "status_ok": 200 <= response.status_code < 400,
        "response_time_ms": round(duration_ms, 2),
        "scheme": scheme,
        "tls_verified": tls_verified,
        "server": headers.get("server"),
        "headers": headers,
        "redirected": bool(response.history),
        "attempts": attempts,
        "note": note,
    }


async def _http_check(domain: str, ips: list[str]) -> dict[str, Any]:
    https_url = f"https://{domain}"
    http_url = f"http://{domain}"
    base: dict[str, Any] = {
        "url": https_url,
        "available": False,
        "reachable": False,
        "status_code": None,
        "status_ok": False,
        "response_time_ms": None,
        "attempts": [],
    }

    if not ips:
        return {
            **base,
            "skipped": True,
            "error": "Aucune adresse IP trouvée pour ce domaine.",
        }

    if not any(_is_public_ip(ip) for ip in ips):
        return {
            **base,
            "skipped": True,
            "error": "Adresse IP non publique : requête bloquée par sécurité.",
        }

    attempts: list[dict[str, str]] = []
    https_error: httpx.RequestError | None = None

    try:
        response, duration_ms = await _http_attempt(
            https_url, True, HTTP_TIMEOUT_SECONDS
        )
        return _http_summary(response, duration_ms, "https", True, attempts)
    except httpx.RequestError as exc:
        https_error = exc
        attempts.append({"url": https_url, "error": type(exc).__name__})

    if https_error is not None and _looks_like_tls_error(https_error):
        try:
            response, duration_ms = await _http_attempt(
                https_url, False, HTTP_TIMEOUT_SECONDS
            )
            return _http_summary(response, duration_ms, "https", False, attempts)
        except httpx.RequestError as exc:
            attempts.append(
                {
                    "url": f"{https_url} (sans vérification)",
                    "error": type(exc).__name__,
                }
            )

    try:
        response, duration_ms = await _http_attempt(
            http_url, True, HTTP_TIMEOUT_SECONDS
        )
        return _http_summary(response, duration_ms, "http", None, attempts)
    except httpx.RequestError as exc:
        attempts.append({"url": http_url, "error": type(exc).__name__})

    last_error = attempts[-1]["error"] if attempts else "RequestError"
    return {
        **base,
        "attempts": attempts,
        "error": f"Aucune réponse en HTTPS ni en HTTP ({last_error}).",
    }


# ---------------------------------------------------------------------------
# Sous-domaines
# ---------------------------------------------------------------------------


async def _crt_sh_subdomains(domain: str) -> set[str]:
    """Récupère les noms vus dans les journaux de certificats (crt.sh)."""
    try:
        async with httpx.AsyncClient(
            timeout=CRTSH_TIMEOUT_SECONDS,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            response = await client.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
            )
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError):
        return set()

    if not isinstance(payload, list):
        return set()

    found: set[str] = set()
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        for key in ("name_value", "common_name"):
            value = entry.get(key)
            if not value:
                continue
            for name in str(value).splitlines():
                name = name.strip().lower().rstrip(".")
                if name.startswith("*."):
                    name = name[2:]
                if name.endswith(f".{domain}"):
                    found.add(name)

    return found


async def _probe_subdomains(domain: str) -> set[str]:
    """Dernier recours : teste quelques préfixes courants en DNS."""
    resolver = _new_resolver()
    semaphore = asyncio.Semaphore(10)

    async def probe(prefix: str) -> str | None:
        name = f"{prefix}.{domain}"
        async with semaphore:
            try:
                answer = await resolver.resolve(name, "A", lifetime=3)
            except (dns.exception.DNSException, OSError):
                return None
            return name if answer.rrset is not None else None

    results = await asyncio.gather(
        *(probe(prefix) for prefix in COMMON_SUBDOMAINS)
    )
    return {name for name in results if name}


def _keep_subdomain(name: str, domain: str) -> str | None:
    name = name.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if name.endswith(f".{domain}"):
        return name
    return None


async def _collect_subdomains(
    domain: str,
    certificate_names: list[str],
    crt_names: set[str],
    probed_names: set[str],
) -> tuple[list[str], int, str]:
    found: set[str] = set()
    sources: list[str] = []

    cert_found = {
        kept
        for name in certificate_names
        if (kept := _keep_subdomain(name, domain))
    }
    if cert_found:
        found |= cert_found
        sources.append("certificat TLS")

    if crt_names:
        found |= crt_names
        sources.append("crt.sh")

    if probed_names:
        found |= probed_names
        sources.append("préfixes courants")

    ordered = sorted(found)
    return (
        ordered[:MAX_SUBDOMAINS],
        len(ordered),
        " + ".join(sources) or "aucune source",
    )


# ---------------------------------------------------------------------------
# Scan de ports
# ---------------------------------------------------------------------------


async def _resolve_addresses(domain: str) -> list[str]:
    resolver = _new_resolver()
    fallback = _new_resolver(use_public=False)
    ipv4, ipv6 = await asyncio.gather(
        _resolve_type(resolver, domain, "A", fallback),
        _resolve_type(resolver, domain, "AAAA", fallback),
    )
    addresses = list(dict.fromkeys(ipv4 + ipv6))

    if not addresses:
        addresses = await _system_addresses(domain)

    return addresses


def _parse_ports(spec: str | None) -> list[int]:
    if not spec or not spec.strip():
        return list(COMMON_PORTS)

    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue

        try:
            if "-" in chunk:
                start_text, end_text = chunk.split("-", 1)
                start, end = int(start_text), int(end_text)
                if start < 1 or end > 65535 or start > end:
                    raise ValueError
                ports.update(range(start, end + 1))
            else:
                port = int(chunk)
                if not 1 <= port <= 65535:
                    raise ValueError
                ports.add(port)
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail=f"Plage de ports invalide : {chunk}",
            ) from exc

    if not ports:
        raise HTTPException(status_code=422, detail="Aucun port valide demandé.")

    if len(ports) > MAX_SCAN_PORTS:
        raise HTTPException(
            status_code=422,
            detail=f"Maximum {MAX_SCAN_PORTS} ports par scan.",
        )

    return sorted(ports)


def _service_name(port: int) -> str | None:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return None


async def _resolve_scan_target(
    target: str,
) -> tuple[str, list[str], list[str], bool]:
    value = target.strip().lower().rstrip(".")
    if not value:
        raise HTTPException(status_code=422, detail="Cible vide.")

    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        domain = _normalize_domain(value)
        addresses = await _resolve_addresses(domain)
        target_type = "domain"
    else:
        addresses = [str(ip)]
        target_type = "ip"

    if not addresses:
        raise HTTPException(
            status_code=400,
            detail="La cible ne résout vers aucune adresse IP.",
        )

    scanned: list[str] = []
    skipped: list[str] = []

    for address in addresses:
        if _is_public_ip(address) or ALLOW_PRIVATE_SCAN:
            scanned.append(address)
        else:
            skipped.append(address)

    if not scanned:
        raise HTTPException(
            status_code=400,
            detail=(
                "Adresse non publique : scan bloqué. "
                "Définissez ALLOW_PRIVATE_SCAN=1 pour autoriser "
                "les réseaux privés."
            ),
        )

    truncated = len(scanned) > MAX_SCAN_HOSTS
    return target_type, scanned[:MAX_SCAN_HOSTS], skipped, truncated


async def _probe_port(
    ip: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> dict[str, Any] | None:
    started = perf_counter()

    try:
        async with semaphore:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
    except (TimeoutError, OSError):
        return None

    latency_ms = (perf_counter() - started) * 1000
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass

    return {
        "port": port,
        "service": _service_name(port),
        "latency_ms": round(latency_ms, 2),
    }


async def _scan_host(
    ip: str,
    ports: list[int],
    timeout: float,
    semaphore: asyncio.Semaphore | None = None,
) -> dict[str, Any]:
    started = perf_counter()
    limiter = semaphore or asyncio.Semaphore(MAX_PARALLEL_SCANS)
    results = await asyncio.gather(
        *(_probe_port(ip, port, timeout, limiter) for port in ports)
    )
    open_ports = sorted(
        (result for result in results if result is not None),
        key=lambda item: item["port"],
    )

    return {
        "ip": ip,
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "duration_ms": round((perf_counter() - started) * 1000, 2),
    }


async def scan_target(
    target: str,
    ports_spec: str | None,
    timeout: float,
) -> dict[str, Any]:
    started = perf_counter()
    ports = _parse_ports(ports_spec)
    target_type, addresses, skipped, truncated = await _resolve_scan_target(target)

    hosts = await asyncio.gather(
        *(_scan_host(ip, ports, timeout) for ip in addresses)
    )

    return {
        "target": target.strip().lower().rstrip("."),
        "target_type": target_type,
        "ips": addresses,
        "skipped_ips": skipped,
        "hosts_truncated": truncated,
        "ports_scanned": len(ports),
        "timeout_seconds": timeout,
        "checked_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "duration_ms": round((perf_counter() - started) * 1000, 2),
        "hosts": list(hosts),
    }


# ---------------------------------------------------------------------------
# Audit + cache
# ---------------------------------------------------------------------------


async def audit_domain(domain: str) -> dict[str, Any]:
    started = perf_counter()

    records, dns_ms = await _resolve_dns(domain)
    ips = list(dict.fromkeys(records.get("A", []) + records.get("AAAA", [])))

    crt_task = asyncio.create_task(_crt_sh_subdomains(domain))
    probe_task = asyncio.create_task(_probe_subdomains(domain))
    tls_task = (
        asyncio.to_thread(_fetch_certificate, domain)
        if any(_is_public_ip(ip) for ip in ips)
        else asyncio.create_task(_skipped_tls())
    )
    http_task = asyncio.create_task(_http_check(domain, ips))
    reverse_task = asyncio.create_task(_reverse_dns_many(ips[:2]))

    tls, http, reverse, crt_names, probed_names = await asyncio.gather(
        tls_task, http_task, reverse_task, crt_task, probe_task
    )

    subdomains, subdomains_total, subdomains_source = await _collect_subdomains(
        domain, tls.get("san", []), crt_names, probed_names
    )

    total_ms = (perf_counter() - started) * 1000

    return {
        "domain": domain,
        "checked_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "available": http["available"],
        "reachable": http.get("reachable", False),
        "status_code": http["status_code"],
        "response_time_ms": http["response_time_ms"],
        "ips": ips,
        "server": {
            "primary_ip": ips[0] if ips else None,
            "reverse_dns": reverse,
            "http_header": http.get("server"),
        },
        "http": http,
        "tls": tls,
        "timings": {
            "dns_ms": round(dns_ms, 2),
            "http_ms": http.get("response_time_ms"),
            "total_ms": round(total_ms, 2),
        },
        "dns": records,
        "subdomains": subdomains,
        "subdomains_total": subdomains_total,
        "subdomains_source": subdomains_source,
    }


def _cache_get(key: str) -> dict[str, Any] | None:
    cached = _cache.get(key)
    if cached and cached[0] > monotonic():
        return cached[1]
    return None


def _cache_set(key: str, value: dict[str, Any]) -> None:
    _cache[key] = (monotonic() + CACHE_TTL_SECONDS, value)

    if len(_cache) > 128:
        now = monotonic()
        for existing, (expires, _) in list(_cache.items()):
            if expires <= now:
                _cache.pop(existing, None)


async def get_audit(domain: str, refresh: bool = False) -> dict[str, Any]:
    domain = _normalize_domain(domain)

    if not refresh:
        cached = _cache_get(domain)
        if cached is not None:
            return cached

    report = await audit_domain(domain)
    _cache_set(domain, report)
    return report


async def get_scan(
    target: str,
    ports_spec: str | None,
    timeout: float,
    refresh: bool = False,
) -> dict[str, Any]:
    key = f"scan|{target.strip().lower()}|{ports_spec or ''}|{timeout}"

    if not refresh:
        cached = _cache_get(key)
        if cached is not None:
            return cached

    report = await scan_target(target, ports_spec, timeout)
    _cache_set(key, report)
    return report


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


def _pdf_safe(value: Any) -> str:
    """Les polices PDF de base sont en Latin-1 : on remplace le reste."""
    text = "" if value is None else str(value)
    return text.encode("latin-1", "replace").decode("latin-1")


def _format_ms(value: float | None) -> str:
    if value is None:
        return "non mesuré"
    return f"{value:.2f} ms"


class _ReportPDF(FPDF):
    def footer(self) -> None:
        self.set_y(-13)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 128, 140)
        self.cell(
            0, 6, _pdf_safe(f"Domain Pulse - page {self.page_no()}"), align="R"
        )


def _pdf_cover(pdf: FPDF, subtitle: str) -> None:
    pdf.set_fill_color(37, 99, 235)
    pdf.rect(0, 0, pdf.w, 36, style="F")
    pdf.set_xy(15, 11)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 10, "Domain Pulse")
    pdf.set_xy(15, 22)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, _pdf_safe(subtitle))
    pdf.set_y(44)
    pdf.set_text_color(23, 32, 51)


def _pdf_section(pdf: FPDF, title: str) -> None:
    if pdf.get_y() > pdf.h - 45:
        pdf.add_page()

    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(23, 32, 51)
    pdf.cell(0, 7, _pdf_safe(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    y = pdf.get_y()
    pdf.set_draw_color(37, 99, 235)
    pdf.set_line_width(0.5)
    pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
    pdf.set_line_width(0.2)
    pdf.ln(2.5)


def _pdf_row(pdf: FPDF, label: str, value: Any, label_width: float = 48) -> None:
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(label_width, 5.6, _pdf_safe(label))

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(15, 23, 42)
    text = _pdf_safe(value) or "-"
    pdf.multi_cell(0, 5.6, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def build_pdf_report(report: dict[str, Any]) -> bytes:
    pdf = _ReportPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(15, 15, 15)
    pdf.add_page()

    _pdf_cover(pdf, "Rapport d'audit de domaine")

    _pdf_row(pdf, "Domaine", report.get("domain"))
    _pdf_row(pdf, "Audité le", report.get("checked_at"))
    status = report.get("status_code")
    availability = "Disponible" if report.get("available") else "Indisponible"
    _pdf_row(
        pdf,
        "Disponibilité",
        f"{availability} (HTTP {status})" if status else availability,
    )

    _pdf_section(pdf, "Temps de réponse")
    timings = report.get("timings") or {}
    _pdf_row(pdf, "Résolution DNS", _format_ms(timings.get("dns_ms")))
    _pdf_row(pdf, "Requête HTTP", _format_ms(timings.get("http_ms")))
    _pdf_row(pdf, "Total", _format_ms(timings.get("total_ms")))

    _pdf_section(pdf, "Réseau et serveur")
    server = report.get("server") or {}
    http = report.get("http") or {}
    _pdf_row(pdf, "Adresses IP", ", ".join(report.get("ips") or []) or "aucune")
    _pdf_row(
        pdf,
        "DNS inverse",
        ", ".join(server.get("reverse_dns") or []) or "non trouvé",
    )
    _pdf_row(pdf, "En-tête serveur", server.get("http_header") or "non exposé")
    _pdf_row(pdf, "URL finale", http.get("url") or "-")
    _pdf_row(pdf, "Schéma", http.get("scheme") or "-")
    if http.get("note"):
        _pdf_row(pdf, "Note HTTP", http["note"])
    if http.get("error"):
        _pdf_row(pdf, "Erreur HTTP", http["error"])

    _pdf_section(pdf, "Certificat TLS")
    tls = report.get("tls") or {}
    if tls.get("subject") or tls.get("issuer"):
        _pdf_row(pdf, "Sujet (CN)", tls.get("subject") or "-")
        _pdf_row(pdf, "Émetteur", tls.get("issuer") or "-")
        _pdf_row(pdf, "Expire le", tls.get("expires_at") or "-")
        days_left = tls.get("days_left")
        _pdf_row(
            pdf,
            "Jours restants",
            f"{days_left} jour(s)" if days_left is not None else "-",
        )
        _pdf_row(
            pdf,
            "Protocole",
            " / ".join(
                part for part in (tls.get("protocol"), tls.get("cipher")) if part
            )
            or "-",
        )
        _pdf_row(pdf, "Noms (SAN)", len(tls.get("san") or []))
        verified = tls.get("verified")
        _pdf_row(
            pdf,
            "Vérifié",
            "Oui" if verified is True else "Non" if verified is False else "n/d",
        )
        if tls.get("error"):
            _pdf_row(pdf, "Avertissement TLS", tls["error"])
    else:
        _pdf_row(
            pdf,
            "Erreur TLS",
            tls.get("error") or "Certificat indisponible.",
        )

    _pdf_section(pdf, "Enregistrements DNS")
    dns_records = report.get("dns") or {}
    if dns_records:
        for rdtype, values in dns_records.items():
            _pdf_row(pdf, rdtype, "\n".join(values) if values else "-")
    else:
        _pdf_row(pdf, "Aucun", "Aucun enregistrement DNS public trouvé.")

    _pdf_section(pdf, "Sous-domaines")
    subdomains = report.get("subdomains") or []
    _pdf_row(pdf, "Source", report.get("subdomains_source") or "-")
    _pdf_row(pdf, "Total", report.get("subdomains_total") or 0)
    if subdomains:
        _pdf_row(pdf, "Détail", "\n".join(subdomains))
    else:
        _pdf_row(pdf, "Détail", "Aucun sous-domaine détecté.")

    pdf.ln(6)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(120, 128, 140)
    pdf.multi_cell(
        0,
        4.5,
        _pdf_safe(
            "Rapport généré automatiquement par Domain Pulse. "
            "Les données DNS et TLS peuvent évoluer après l'analyse."
        ),
    )

    return bytes(pdf.output())


def build_scan_pdf_report(report: dict[str, Any]) -> bytes:
    pdf = _ReportPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(15, 15, 15)
    pdf.add_page()
    _pdf_cover(pdf, "Rapport de scan de ports")

    _pdf_row(pdf, "Cible", report.get("target"))
    _pdf_row(pdf, "Type", report.get("target_type") or "-")
    _pdf_row(pdf, "Analysé le", report.get("checked_at"))
    _pdf_row(pdf, "Adresses", ", ".join(report.get("ips") or []) or "aucune")
    _pdf_row(pdf, "Ports scannés", report.get("ports_scanned") or 0)
    _pdf_row(
        pdf,
        "Délai par port",
        f"{report.get('timeout_seconds') or 0:.1f} s",
    )
    _pdf_row(pdf, "Durée totale", _format_ms(report.get("duration_ms")))

    if report.get("hosts_truncated"):
        _pdf_row(
            pdf,
            "Note",
            f"Seuls les {MAX_SCAN_HOSTS} premiers hôtes ont été scannés.",
        )
    if report.get("skipped_ips"):
        _pdf_row(
            pdf,
            "Adresses ignorées",
            ", ".join(report["skipped_ips"]),
        )

    hosts = report.get("hosts") or []
    if not hosts:
        _pdf_row(pdf, "Hôtes", "Aucun hôte à scanner.")

    for host in hosts:
        _pdf_section(pdf, f"Hôte {host.get('ip') or 'inconnu'}")
        _pdf_row(pdf, "Ports ouverts", host.get("open_count") or 0)

        open_ports = host.get("open_ports") or []
        if open_ports:
            for item in open_ports:
                service = item.get("service") or "inconnu"
                _pdf_row(
                    pdf,
                    f"Port {item.get('port')}",
                    f"{service} - {_format_ms(item.get('latency_ms'))}",
                )
        else:
            _pdf_row(pdf, "Détail", "Aucun port ouvert détecté.")

        _pdf_row(pdf, "Durée du scan", _format_ms(host.get("duration_ms")))

    pdf.ln(6)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(120, 128, 140)
    pdf.multi_cell(
        0,
        4.5,
        _pdf_safe(
            "Scan TCP réalisé par Domain Pulse. Seuls les ports demandés ont "
            "été testés ; un port filtré peut apparaître comme fermé."
        ),
    )

    return bytes(pdf.output())


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/check")
async def check(
    domain: str = DOMAIN_QUERY,
    refresh: bool = Query(False, description="Ignorer le cache de 5 minutes"),
):
    return await get_audit(domain, refresh=refresh)


@app.get("/report.pdf")
async def report_pdf(
    domain: str = DOMAIN_QUERY,
    refresh: bool = Query(False, description="Ignorer le cache de 5 minutes"),
):
    report = await get_audit(domain, refresh=refresh)
    content = build_pdf_report(report)

    return Response(
        content=content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="domain-pulse-{domain}.pdf"'
            )
        },
    )


@app.get("/scan")
async def scan(
    target: str = Query(
        ...,
        min_length=1,
        max_length=253,
        description="Adresse IP ou nom de domaine à scanner",
    ),
    ports: str | None = Query(
        None,
        description=(
            "Ports à tester, ex. 22,80,443 ou 1-1024 "
            f"(maximum {MAX_SCAN_PORTS} ports)"
        ),
    ),
    timeout: float = Query(
        DEFAULT_SCAN_TIMEOUT,
        ge=0.2,
        le=2.0,
        description="Délai de connexion par port en secondes",
    ),
    refresh: bool = Query(False, description="Ignorer le cache de 5 minutes"),
):
    return await get_scan(target, ports, timeout, refresh=refresh)


@app.get("/scan/report.pdf")
async def scan_report_pdf(
    target: str = Query(
        ...,
        min_length=1,
        max_length=253,
        description="Adresse IP ou nom de domaine à scanner",
    ),
    ports: str | None = Query(
        None,
        description=(
            "Ports à tester, ex. 22,80,443 ou 1-1024 "
            f"(maximum {MAX_SCAN_PORTS} ports)"
        ),
    ),
    timeout: float = Query(
        DEFAULT_SCAN_TIMEOUT,
        ge=0.2,
        le=2.0,
        description="Délai de connexion par port en secondes",
    ),
    refresh: bool = Query(False, description="Ignorer le cache de 5 minutes"),
):
    report = await get_scan(target, ports, timeout, refresh=refresh)
    content = build_scan_pdf_report(report)
    filename = report["target"].replace(":", "-")

    return Response(
        content=content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="domain-pulse-scan-{filename}.pdf"'
            )
        },
    )
