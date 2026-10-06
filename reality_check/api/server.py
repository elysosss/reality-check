"""Серверные вызовы панели: статус, применённый конфиг Xray, генераторы ключей.

Расположение этих эндпоинтов различается между ветками 3x-ui:
  * старые: POST /server/status, POST /server/getNewX25519Cert;
  * новые:  GET  /panel/api/server/status, GET /panel/api/server/getNewX25519Cert.
Поэтому каждый вызов — список кандидатов, первый сработавший запоминается на
время жизни клиента, чтобы не перебирать заново.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable

from .client import XUIClient, XUIError

log = logging.getLogger(__name__)

_resolved: dict[tuple[int, str], tuple[str, str]] = {}

STATUS = [("GET", "/panel/api/server/status"), ("POST", "/server/status"), ("GET", "/server/status")]
CONFIG_JSON = [
    ("GET", "/panel/api/server/getConfigJson"),
    ("POST", "/server/getConfigJson"),
]
XRAY_VERSIONS = [
    ("GET", "/panel/api/server/getXrayVersion"),
    ("POST", "/server/getXrayVersion"),
]
NEW_UUID = [("GET", "/panel/api/server/getNewUUID"), ("POST", "/server/getNewUUID")]
NEW_X25519 = [
    ("GET", "/panel/api/server/getNewX25519Cert"),
    ("POST", "/server/getNewX25519Cert"),
]


def call(cli: XUIClient, key: str, candidates: Iterable[tuple[str, str]]) -> Any:
    """Пробует кандидатов по очереди и запоминает сработавшего."""
    cache_key = (id(cli), key)
    known = _resolved.get(cache_key)
    order = [known] if known else list(candidates)
    last_error: str = ""
    for method, path in order:
        try:
            obj = cli.request(method, path)
        except XUIError as e:
            last_error = e.message
            continue
        _resolved[cache_key] = (method, path)
        return obj
    if known:
        _resolved.pop(cache_key, None)
        return call(cli, key, candidates)
    raise XUIError(f"ни один из вариантов эндпоинта '{key}' не отработал: {last_error}")


def status(cli: XUIClient) -> dict:
    obj = call(cli, "status", STATUS)
    return obj if isinstance(obj, dict) else {}


def config_json(cli: XUIClient) -> dict:
    """Конфиг Xray, реально применённый на сервере. Ценен тем, что не требует SSH."""
    obj = call(cli, "config", CONFIG_JSON)
    return obj if isinstance(obj, dict) else {}


def xray_versions(cli: XUIClient) -> list[str]:
    obj = call(cli, "versions", XRAY_VERSIONS)
    return [str(v) for v in obj] if isinstance(obj, list) else []


def new_uuid(cli: XUIClient) -> str:
    obj = call(cli, "uuid", NEW_UUID)
    if isinstance(obj, str):
        return obj.strip()
    if isinstance(obj, dict):
        return str(obj.get("uuid") or obj.get("id") or "")
    return ""


def new_x25519(cli: XUIClient) -> dict[str, str]:
    obj = call(cli, "x25519", NEW_X25519)
    if not isinstance(obj, dict):
        raise XUIError("панель вернула не пару ключей Reality")
    private = obj.get("privateKey") or obj.get("PrivateKey") or ""
    public = obj.get("publicKey") or obj.get("PublicKey") or ""
    if not private:
        raise XUIError("в ответе нет приватного ключа Reality")
    return {"privateKey": str(private), "publicKey": str(public)}


def xray_logs(cli: XUIClient, count: int = 200) -> list[str]:
    """Последние строки лога Xray прямо из панели — работает и там, где нет SSH."""
    for method, path in (
        ("POST", f"/panel/api/server/xraylogs/{count}"),
        ("GET", f"/panel/api/server/xraylogs/{count}"),
        ("POST", f"/panel/api/server/logs/{count}"),
    ):
        try:
            obj = cli.request(method, path, allow_fail=True)
        except XUIError:
            continue
        if isinstance(obj, list):
            return [str(x) for x in obj]
        if isinstance(obj, str) and obj.strip():
            return obj.splitlines()
    return []


def error_lines(lines: list[str]) -> list[str]:
    """Строки лога, похожие на ошибку, — чтобы не листать всё подряд."""
    маркеры = ("error", "failed", "rejected", "invalid", "refused", "panic", "denied")
    return [l for l in lines if any(m in l.lower() for m in маркеры)]


def xray_state(cli: XUIClient) -> dict[str, Any]:
    """Состояние Xray из статуса панели, приведённое к общему виду."""
    st = status(cli)
    xray = st.get("xray") if isinstance(st.get("xray"), dict) else {}
    public = st.get("publicIP") if isinstance(st.get("publicIP"), dict) else {}
    return {
        "state": xray.get("state"),
        "version": xray.get("version"),
        "error": xray.get("errorMsg") or "",
        "uptime_sec": st.get("uptime"),
        "panel_version": st.get("panelVersion"),
        # адрес, которым сервер выходит наружу: с ним сверяется внешний IP в e2e-тесте
        "public_ip": public.get("ipv4") or "",
        "raw_keys": sorted(st.keys())[:24],
    }
