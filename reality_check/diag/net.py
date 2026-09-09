"""Сетевые пробы снаружи, с этой машины.

Смысл этих проверок появляется только в паре с такими же проверками на самом
сервере (diag/host.py): расхождение «изнутри слушает / снаружи не достучаться»
однозначно указывает на фильтрацию между нами и сервером.
"""
from __future__ import annotations

import socket
import ssl
import time
from typing import Any


def resolve(host: str) -> dict[str, Any]:
    """A/AAAA-записи имени. Для IP вернёт его же."""
    out: dict[str, Any] = {"host": host, "addresses": [], "ok": False}
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = sorted({info[4][0] for info in infos})
        out["addresses"] = addrs
        out["ok"] = bool(addrs)
    except socket.gaierror as e:
        out["error"] = f"DNS не разрешает имя: {e}"
    return out


def tcp_connect(host: str, port: int, timeout: float = 6.0) -> dict[str, Any]:
    """Обычный TCP-коннект. Различает 'refused' (порт закрыт) и таймаут (фильтрация)."""
    out: dict[str, Any] = {"host": host, "port": port, "ok": False}
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            out["ok"] = True
            out["rtt_ms"] = round((time.perf_counter() - start) * 1000, 1)
    except socket.timeout:
        out["error"] = "таймаут"
        out["hint"] = "пакеты уходят в никуда — фаервол/облачная security group режет молча, либо DPI"
    except ConnectionRefusedError:
        out["error"] = "connection refused"
        out["hint"] = "порт закрыт: на этом порту никто не слушает"
    except OSError as e:
        out["error"] = f"{type(e).__name__}: {e}"
    out["elapsed_ms"] = round((time.perf_counter() - start) * 1000, 1)
    return out


def tls_handshake(host: str, port: int, sni: str = "", timeout: float = 8.0) -> dict[str, Any]:
    """TLS-хендшейк с указанным SNI. Сертификат не проверяем — нам нужны факты, не доверие.

    Для Reality ожидаемое поведение — увидеть сертификат чужого сайта (dest):
    именно так маскировка и выглядит снаружи.
    """
    out: dict[str, Any] = {"host": host, "port": port, "sni": sni or host, "ok": False}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni or host) as tls:
                out["ok"] = True
                out["tls_version"] = tls.version()
                out["cipher"] = tls.cipher()[0] if tls.cipher() else None
                out["alpn"] = tls.selected_alpn_protocol()
                cert = tls.getpeercert()
                if cert:
                    out["cert_subject"] = _cert_name(cert.get("subject"))
                    out["cert_issuer"] = _cert_name(cert.get("issuer"))
                    out["cert_not_after"] = cert.get("notAfter")
                    out["cert_san"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:6]
                else:
                    der = tls.getpeercert(binary_form=True)
                    out["cert_note"] = "сертификат получен, но без разбора" if der else "сертификат не предъявлен"
    except ssl.SSLError as e:
        out["error"] = f"TLS-ошибка: {e}"
        out["hint"] = "порт открыт, но TLS не сложился — не тот SNI, не тот протокол на порту или обрыв на DPI"
    except socket.timeout:
        out["error"] = "таймаут хендшейка"
        out["hint"] = "TCP есть, TLS не отвечает — характерно для активной фильтрации"
    except OSError as e:
        out["error"] = f"{type(e).__name__}: {e}"
    out["elapsed_ms"] = round((time.perf_counter() - start) * 1000, 1)
    return out


def _cert_name(name: Any) -> str:
    if not name:
        return ""
    parts = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def http_probe(url: str, timeout: float = 8.0, proxy: str | None = None) -> dict[str, Any]:
    """HTTP-запрос, опционально через SOCKS5-прокси (для e2e-проверки)."""
    import requests

    out: dict[str, Any] = {"url": url, "ok": False}
    proxies = {"http": proxy, "https": proxy} if proxy else None
    start = time.perf_counter()
    try:
        r = requests.get(url, timeout=timeout, proxies=proxies, allow_redirects=False)
        out["ok"] = True
        out["status"] = r.status_code
        out["body"] = r.text[:200]
        out["ms"] = round((time.perf_counter() - start) * 1000, 1)
    except Exception as e:  # requests заворачивает и socks-ошибки
        out["error"] = f"{type(e).__name__}: {e}"
        out["ms"] = round((time.perf_counter() - start) * 1000, 1)
    return out


def wait_port(host: str, port: int, timeout: float = 10.0, interval: float = 0.25) -> bool:
    """Ждём, пока локальный порт начнёт принимать соединения (запуск xray)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(interval)
    return False


def free_port(preferred: int = 10808) -> int:
    """Свободный локальный порт: предпочитаем привычный, иначе просим у системы."""
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            pass
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
