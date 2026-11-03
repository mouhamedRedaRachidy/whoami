"""Domain Pulse - audit complet d'un nom de domaine.

Expose :
- ``/``          : interface web
- ``/health``    : sonde de disponibilité
- ``/check``     : audit JSON (DNS, IP, serveur, TLS, temps, sous-domaines,
                   ports TCP courants des IP publiques du domaine)
- ``/report.pdf``: dernier audit du domaine au format PDF (sans nouveau scan)
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

# Analyse automatique des ports TCP (liste fixe, aucune saisie utilisateur)
PORT_SCAN_TIMEOUT_SECONDS = 2.0
PORT_SCAN_MAX_CONNECTIONS = 10
PORT_SCAN_MAX_IPS = 4
REPORT_TTL_SECONDS = 3600

# Nom du service *habituellement* associé au port : purement indicatif.
PORT_SERVICES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS (TCP)",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP (soumission)",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP alternatif",
    8080: "HTTP alternatif",
    8443: "HTTPS alternatif",
}
SCAN_PORTS: tuple[int, ...] = tuple(PORT_SERVICES)

PORT_STATE_LABELS = {
    "open": "ouvert",
    "refused": "connexion refusée",
    "timeout": "délai dépassé",
    "error": "erreur réseau",
}

PORT_SCAN_NOTES = (
    "Test TCP uniquement : un port testé en TCP ne dit rien du même port en "
    "UDP (par exemple, le port 53 en TCP ne vérifie pas le DNS en UDP).",
    "Le nom du service est indicatif : il correspond à l'usage habituel du "
    "port, pas au logiciel réellement en écoute.",
    "Les adresses IP peuvent appartenir à un CDN ou à un proxy (Cloudflare, "
    "load balancer...) et ne représentent pas forcément le serveur d'origine.",
    "« Délai dépassé » signifie souvent qu'un pare-feu ignore la connexion ; "
    "« connexion refusée » signifie que la machine répond mais que rien "
    "n'écoute sur ce port.",
    "N'analysez que des domaines que vous possédez ou que vous êtes autorisé "
    "à tester. Aucune plage réseau n'est scannée : seules les IP du domaine "
    "sont testées.",
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
    """Vrai seulement pour une adresse routable sur Internet.

    Refuse les adresses privées, locales, réservées, partagées (CGNAT) et
    multicast, y compris sous forme IPv4 encapsulée dans IPv6 (::ffff:a.b.c.d).
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False

    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    return ip.is_global and not ip.is_multicast


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
# Ports TCP (scan automatique des IP du domaine)
# ---------------------------------------------------------------------------


def _select_scan_ips(ips: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Répartit les IP du domaine : testées, non testées (limite), refusées.

    Seules les IP publiques sont retenues. IPv4 et IPv6 sont alternées pour
    que les deux familles soient représentées quand la limite est atteinte.
    """
    unique = list(dict.fromkeys(ips))
    public = [ip for ip in unique if _is_public_ip(ip)]
    rejected = [ip for ip in unique if not _is_public_ip(ip)]

    ipv4 = [ip for ip in public if ":" not in ip]
    ipv6 = [ip for ip in public if ":" in ip]
    ordered: list[str] = []
    for index in range(max(len(ipv4), len(ipv6))):
        ordered.extend(family[index] for family in (ipv4, ipv6) if index < len(family))

    return ordered[:PORT_SCAN_MAX_IPS], ordered[PORT_SCAN_MAX_IPS:], rejected


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    """Ferme proprement la connexion, sans jamais bloquer l'analyse."""
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except (OSError, TimeoutError):
        writer.transport.abort()


async def _probe_port(
    ip: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> dict[str, Any]:
    """Tente une connexion TCP et classe le résultat (ouvert/refusé/délai)."""
    result: dict[str, Any] = {
        "port": port,
        "service": PORT_SERVICES.get(port, "inconnu"),
        "latency_ms": None,
    }

    async with semaphore:
        started = perf_counter()
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
        except TimeoutError:
            return {**result, "state": "timeout"}
        except ConnectionRefusedError:
            return {**result, "state": "refused"}
        except OSError as exc:
            return {
                **result,
                "state": "error",
                "error": exc.strerror or type(exc).__name__,
            }

        latency_ms = (perf_counter() - started) * 1000
        await _close_writer(writer)

    return {**result, "state": "open", "latency_ms": round(latency_ms, 2)}


async def _scan_host(
    ip: str,
    ports: tuple[int, ...] | list[int],
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> dict[str, Any]:
    started = perf_counter()
    results = await asyncio.gather(
        *(_probe_port(ip, port, timeout, semaphore) for port in ports)
    )
    results = sorted(results, key=lambda item: item["port"])

    def ports_in(state: str) -> list[int]:
        return [item["port"] for item in results if item["state"] == state]

    open_ports = [item for item in results if item["state"] == "open"]
    return {
        "ip": ip,
        "version": ipaddress.ip_address(ip).version,
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "refused_ports": ports_in("refused"),
        "timeout_ports": ports_in("timeout"),
        "error_ports": [
            {"port": item["port"], "error": item.get("error")}
            for item in results
            if item["state"] == "error"
        ],
        "duration_ms": round((perf_counter() - started) * 1000, 2),
    }


async def scan_ports(ips: list[str]) -> dict[str, Any]:
    """Teste la liste fixe de ports TCP sur les IP publiques du domaine."""
    started = perf_counter()
    selected, not_scanned, rejected = _select_scan_ips(ips)

    summary: dict[str, Any] = {
        "protocol": "TCP",
        "ports": list(SCAN_PORTS),
        "timeout_seconds": PORT_SCAN_TIMEOUT_SECONDS,
        "max_connections": PORT_SCAN_MAX_CONNECTIONS,
        "max_ips": PORT_SCAN_MAX_IPS,
        "scanned_ips": selected,
        "not_scanned_ips": not_scanned,
        "rejected_ips": rejected,
        "hosts": [],
        "skipped": False,
        "error": None,
        "notes": list(PORT_SCAN_NOTES),
        "duration_ms": 0.0,
    }

    if not selected:
        summary["skipped"] = True
        summary["error"] = (
            "Aucune adresse IP publique : scan des ports non effectué par sécurité."
            if ips
            else "Aucune adresse IP trouvée : scan des ports non effectué."
        )
        return summary

    semaphore = asyncio.Semaphore(PORT_SCAN_MAX_CONNECTIONS)
    hosts = await asyncio.gather(
        *(
            _scan_host(ip, SCAN_PORTS, PORT_SCAN_TIMEOUT_SECONDS, semaphore)
            for ip in selected
        )
    )

    summary["hosts"] = list(hosts)
    summary["duration_ms"] = round((perf_counter() - started) * 1000, 2)
    return summary


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
    ports_task = asyncio.create_task(scan_ports(ips))

    tls, http, reverse, crt_names, probed_names, ports = await asyncio.gather(
        tls_task, http_task, reverse_task, crt_task, probe_task, ports_task
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
        "ports": ports,
    }


def _cache_get(
    key: str, max_age: float = CACHE_TTL_SECONDS
) -> dict[str, Any] | None:
    cached = _cache.get(key)
    if cached and monotonic() - cached[0] < max_age:
        return cached[1]
    return None


def _cache_set(key: str, value: dict[str, Any]) -> None:
    _cache[key] = (monotonic(), value)

    if len(_cache) > 128:
        now = monotonic()
        for existing, (created, _) in list(_cache.items()):
            if now - created >= REPORT_TTL_SECONDS:
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


def get_saved_report(domain: str) -> dict[str, Any]:
    """Rapport déjà calculé pour le PDF : ne relance jamais l'analyse."""
    domain = _normalize_domain(domain)
    report = _cache_get(domain, max_age=REPORT_TTL_SECONDS)
    if report is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "Aucune analyse récente pour ce domaine. Cliquez sur "
                "« Analyser » avant de télécharger le PDF."
            ),
        )
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
    pdf.set_fill_color(124, 58, 237)
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
    pdf.set_draw_color(124, 58, 237)
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


def _format_port_list(ports: list[int]) -> str:
    return ", ".join(str(port) for port in ports) or "aucun"


def _pdf_ports(pdf: FPDF, ports: dict[str, Any]) -> None:
    _pdf_section(pdf, "Ports TCP")
    if not ports:
        _pdf_row(pdf, "Statut", "Scan des ports non disponible pour ce rapport.")
        return

    _pdf_row(
        pdf,
        "Méthode",
        f"Connexion {ports.get('protocol') or 'TCP'} - délai "
        f"{ports.get('timeout_seconds') or 0:.0f} s - "
        f"{ports.get('max_connections') or 0} connexions simultanées max",
    )
    _pdf_row(pdf, "Ports testés", _format_port_list(ports.get("ports") or []))
    _pdf_row(
        pdf, "IP testées", ", ".join(ports.get("scanned_ips") or []) or "aucune"
    )
    if ports.get("not_scanned_ips"):
        _pdf_row(
            pdf,
            "IP non testées",
            f"{', '.join(ports['not_scanned_ips'])} "
            f"(limite de {ports.get('max_ips') or PORT_SCAN_MAX_IPS} IP par analyse)",
        )
    if ports.get("rejected_ips"):
        _pdf_row(
            pdf,
            "IP refusées",
            f"{', '.join(ports['rejected_ips'])} (adresses non publiques)",
        )
    if ports.get("error"):
        _pdf_row(pdf, "Statut", ports["error"])

    for host in ports.get("hosts") or []:
        _pdf_section(pdf, f"Ports TCP - IPv{host.get('version') or '?'} {host.get('ip')}")
        open_ports = host.get("open_ports") or []
        if open_ports:
            for item in open_ports:
                _pdf_row(
                    pdf,
                    f"Port {item.get('port')} ouvert",
                    f"{item.get('service') or 'inconnu'} (indicatif) - "
                    f"connexion en {_format_ms(item.get('latency_ms'))}",
                )
        else:
            _pdf_row(pdf, "Ports ouverts", "Aucun port ouvert détecté.")

        _pdf_row(
            pdf,
            PORT_STATE_LABELS["refused"].capitalize(),
            _format_port_list(host.get("refused_ports") or []),
        )
        _pdf_row(
            pdf,
            PORT_STATE_LABELS["timeout"].capitalize(),
            _format_port_list(host.get("timeout_ports") or []),
        )
        for item in host.get("error_ports") or []:
            _pdf_row(
                pdf,
                f"Port {item.get('port')}",
                f"{PORT_STATE_LABELS['error']} : {item.get('error') or '-'}",
            )

    notes = ports.get("notes") or []
    if notes:
        pdf.ln(2)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(100, 116, 139)
        for note in notes:
            pdf.multi_cell(
                0, 4.5, _pdf_safe(f"- {note}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT
            )


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

    _pdf_ports(pdf, report.get("ports") or {})

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
async def report_pdf(domain: str = DOMAIN_QUERY):
    # Le PDF reprend l'analyse déjà affichée : aucun nouveau scan ici.
    report = get_saved_report(domain)
    content = build_pdf_report(report)

    return Response(
        content=content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="domain-pulse-{report["domain"]}.pdf"'
            )
        },
    )
