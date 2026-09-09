"""Прощупывание панели: что эта конкретная версия 3x-ui реально умеет.

Версии панелей отличаются набором эндпоинтов и способом авторизации, поэтому
вместо предположений мы один раз опрашиваем панель и кэшируем результат в
runs/caps/<server>.json. Дальше остальной код спрашивает возможности у кэша.

Опрашиваются ТОЛЬКО читающие эндпоинты — проба ничего не меняет на сервере.
"""
from __future__ import annotations

import logging
from typing import Any

import requests

from ..config import Server
from ..util import RUNS, read_json, ts, write_json
from . import server as server_api
from .client import AuthError, XUIClient, XUIError

log = logging.getLogger(__name__)

# (ключ, метод, путь) — всё только чтение
CANDIDATES: list[tuple[str, str, str]] = [
    ("inbounds.list", "GET", "/panel/api/inbounds/list"),
    ("inbounds.list_slim", "GET", "/panel/api/inbounds/list/slim"),
    ("inbounds.options", "GET", "/panel/api/inbounds/options"),
    ("inbounds.allLinks", "GET", "/panel/api/inbounds/allLinks"),
    ("inbounds.get1", "GET", "/panel/api/inbounds/get/1"),
    ("inbounds.onlines.post", "POST", "/panel/api/inbounds/onlines"),
    ("inbounds.onlines.get", "GET", "/panel/api/inbounds/onlines"),
    # старая раскладка серверных вызовов
    ("server.status.post", "POST", "/server/status"),
    ("server.xrayVersion.post", "POST", "/server/getXrayVersion"),
    ("server.configJson.post", "POST", "/server/getConfigJson"),
    ("server.newUUID.post", "POST", "/server/getNewUUID"),
    ("server.x25519.post", "POST", "/server/getNewX25519Cert"),
    # новая раскладка: всё под /panel/api/server и методом GET
    ("server.status.new", "GET", "/panel/api/server/status"),
    ("server.xrayVersion.new", "GET", "/panel/api/server/getXrayVersion"),
    ("server.configJson.new", "GET", "/panel/api/server/getConfigJson"),
    ("server.newUUID.new", "GET", "/panel/api/server/getNewUUID"),
    ("server.x25519.new", "GET", "/panel/api/server/getNewX25519Cert"),
]

OPENAPI_PATHS = [
    # ветка 3.x отдаёт спецификацию здесь — по ней и надо строить работу с API
    "/panel/api/openapi.json",
    "/panel/api-docs/openapi.json",
    "/panel/api-docs/swagger.json",
    "/openapi.json",
    "/panel/openapi.json",
    "/public/openapi.json",
]


def _shape(obj: Any) -> str:
    """Короткое описание формы ответа — чтобы отчёт был читаемым, а не дампом."""
    if obj is None:
        return "null"
    if isinstance(obj, list):
        inner = _shape(obj[0]) if obj else "?"
        return f"list[{len(obj)}] of {inner}"
    if isinstance(obj, dict):
        keys = list(obj.keys())[:8]
        return "dict{" + ",".join(str(k) for k in keys) + ("…" if len(obj) > 8 else "") + "}"
    text = str(obj)
    return f"{type(obj).__name__}({text[:40]})"


def probe_server(server: Server, *, save: bool = True) -> dict:
    """Полный отчёт о возможностях панели одного сервера."""
    report: dict[str, Any] = {
        "server": server.name,
        "panel_root": server.panel.root,
        "checked_at": ts(),
        "reachable": False,
        "auth_mode": None,
        "auth_error": None,
        "endpoints": {},
        "openapi": None,
        "panel_info": {},
        "notes": [],
    }

    cli = XUIClient(server)

    # 1. вообще ли отвечает панель по этому URL
    try:
        r = cli.s.get(cli.url("/"), timeout=server.panel.timeout, allow_redirects=True)
        report["reachable"] = True
        report["root_status"] = r.status_code
        report["root_content_type"] = r.headers.get("Content-Type", "")
        if r.status_code == 404:
            report["notes"].append(
                "корень панели отдаёт 404 — скорее всего задан webBasePath, проверь base_path в servers.yaml"
            )
    except requests.RequestException as e:
        report["error"] = f"панель недоступна по HTTP: {type(e).__name__}: {e}"
        report["notes"].append("проверь url/порт панели и что она вообще запущена (diag доберётся до сервера по SSH)")
        if save:
            _save(server, report)
        return report

    # 2. авторизация
    try:
        report["auth_mode"] = cli.ensure_auth()
    except AuthError as e:
        report["auth_error"] = e.message
        report["notes"].append("без авторизации остальные пробы бессмысленны")
        if save:
            _save(server, report)
        return report
    except requests.RequestException as e:
        report["auth_error"] = f"{type(e).__name__}: {e}"
        if save:
            _save(server, report)
        return report

    report["csrf"] = bool(cli.csrf_token)

    # 3. какие эндпоинты живы
    for key, method, path in CANDIDATES:
        entry: dict[str, Any] = {"method": method, "path": path}
        try:
            resp = cli.raw(method, path)
            entry["http"] = resp.status_code
            try:
                body = resp.json()
            except ValueError:
                entry["ok"] = False
                entry["note"] = "ответ не JSON"
                report["endpoints"][key] = entry
                continue
            if isinstance(body, dict) and "success" in body:
                entry["ok"] = bool(body.get("success"))
                if not entry["ok"]:
                    entry["msg"] = str(body.get("msg", ""))[:200]
                else:
                    entry["shape"] = _shape(body.get("obj"))
            else:
                entry["ok"] = resp.status_code == 200
                entry["shape"] = _shape(body)
        except requests.RequestException as e:
            entry["ok"] = False
            entry["note"] = f"{type(e).__name__}: {e}"
        except XUIError as e:
            entry["ok"] = False
            entry["note"] = e.message
        report["endpoints"][key] = entry

    # 4. собственный OpenAPI панели — самый точный источник о её версии API
    for path in OPENAPI_PATHS:
        try:
            resp = cli.raw("GET", path)
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        try:
            spec = resp.json()
        except ValueError:
            continue
        if isinstance(spec, dict) and spec.get("paths"):
            report["openapi"] = {
                "source": path,
                "version": (spec.get("info") or {}).get("version"),
                "title": (spec.get("info") or {}).get("title"),
                "path_count": len(spec["paths"]),
                "paths": sorted(spec["paths"].keys()),
            }
            break

    # 5. сведения о самой панели и Xray (раскладка эндпоинтов определяется автоматически)
    try:
        state = server_api.xray_state(cli)
        report["panel_info"] = state
        if state.get("state") and str(state["state"]).lower() not in ("running", "true"):
            report["notes"].append(
                f"Xray на сервере в состоянии '{state.get('state')}' — это уже причина неработающих конфигов"
            )
        if state.get("error"):
            report["notes"].append(f"Xray сообщает об ошибке: {str(state['error'])[:200]}")
    except XUIError as e:
        report["notes"].append(f"статус сервера недоступен: {e.message}")

    # 6. сводка по инбаундам — попутно проверяем, что данные разбираются
    if (report["endpoints"].get("inbounds.list") or {}).get("ok"):
        try:
            from .inbounds import list_inbounds

            inbounds = list_inbounds(cli)
            report["inbounds"] = [
                {
                    "id": i.id,
                    "remark": i.remark,
                    "protocol": i.protocol,
                    "network": i.network,
                    "security": i.security,
                    "port": i.port,
                    "enable": i.enable,
                    "clients": len(i.clients),
                }
                for i in inbounds
            ]
            broken = [i.id for i in inbounds if i.raw.get("streamSettings") and not i.stream]
            if broken:
                report["notes"].append(f"у инбаундов {broken} не разобрался streamSettings — формат неожиданный")
        except XUIError as e:
            report["notes"].append(f"список инбаундов не прочитался: {e.message}")

    cli.close()
    if save:
        _save(server, report)
    return report


def _save(server: Server, report: dict) -> None:
    write_json(RUNS / "caps" / f"{server.name}.json", report)


def load_caps(server_name: str) -> dict | None:
    path = RUNS / "caps" / f"{server_name}.json"
    return read_json(path) if path.exists() else None


def has(server_name: str, key: str) -> bool:
    """Поддерживает ли панель конкретную возможность по данным последней пробы."""
    caps = load_caps(server_name)
    if not caps:
        return False
    return bool((caps.get("endpoints") or {}).get(key, {}).get("ok"))
