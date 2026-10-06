"""Расхождение между базой панели и конфигом, реально применённым в Xray.

Самый коварный класс поломок: панель показывает клиента, отдаёт по нему ссылку,
API отвечает success — а Xray про этот идентификатор ничего не знает, потому что
работает по другой версии конфига. Снаружи это выглядит как «сервер живой, порт
открыт, а конфиг не работает».

Проверка целиком читающая: сравниваются ответ /panel/api/server/getConfigJson
и список инбаундов из базы панели.
"""
from __future__ import annotations

import base64
from typing import Any

from ..api import server as server_api
from ..api import registry
from ..api.client import XUIClient, XUIError
from ..api.models import Inbound


def _secret(client_raw: dict) -> str:
    """Идентификатор клиента: у vless/vmess это id, у trojan/ss — пароль."""
    return str(client_raw.get("id") or client_raw.get("password") or "")


def derive_public_key(private_key: str) -> str:
    """Публичный ключ Reality из приватного. Нужен, чтобы поймать разъехавшуюся пару."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    except ImportError:
        return ""
    try:
        raw = base64.urlsafe_b64decode(private_key + "=" * (-len(private_key) % 4))
        pub = X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return base64.urlsafe_b64encode(pub).decode().rstrip("=")
    except Exception:
        return ""


def compare(cli: XUIClient, inbounds: list[Inbound]) -> dict[str, Any]:
    """Сверяет базу панели с применённым конфигом. Инбаунды на узлах пропускаются:
    их конфиг живёт на узле, и в конфиге панели их быть не должно."""
    report: dict[str, Any] = {"checked": 0, "skipped_nodes": 0, "findings": [], "error": ""}
    try:
        conf = server_api.config_json(cli)
    except XUIError as e:
        report["error"] = f"применённый конфиг недоступен: {e.message}"
        return report

    applied = {i.get("port"): i for i in (conf.get("inbounds") or []) if isinstance(i, dict)}
    report["applied_ports"] = sorted(p for p in applied if isinstance(p, int))

    for inb in inbounds:
        if inb.node_id:
            report["skipped_nodes"] += 1
            continue
        entry = applied.get(inb.port)
        if entry is None:
            if inb.enable and inb.protocol in ("vless", "vmess", "trojan", "shadowsocks"):
                report["findings"].append({
                    "inbound": inb.id,
                    "port": inb.port,
                    "kind": "инбаунд отсутствует в применённом конфиге",
                    "detail": "включён в панели, но Xray его не поднимал",
                })
            continue

        report["checked"] += 1

        # истина об идентификаторе — таблица клиентов панели: копия внутри инбаунда
        # может устареть, и тогда панель раздаёт нерабочие ссылки через allLinks
        panel_clients = {}
        for c in inb.clients:
            record = registry.get_client(cli, c.email) if c.email else None
            real = registry.secret_of(record, inb.protocol) if record else ""
            if real and real != c.uuid:
                report["findings"].append({
                    "inbound": inb.id, "port": inb.port, "email": c.email,
                    "kind": "копия клиента в инбаунде устарела",
                    "panel": c.uuid, "applied": real,
                    "detail": "ссылки из inbounds/allLinks по нему мертвы; верное значение — в таблице клиентов",
                })
            panel_clients[c.email] = real or c.uuid
        applied_clients = {
            str(c.get("email", "")): _secret(c)
            for c in ((entry.get("settings") or {}).get("clients") or [])
            if isinstance(c, dict)
        }
        for email, uuid in panel_clients.items():
            live = applied_clients.get(email)
            if live is None:
                report["findings"].append({
                    "inbound": inb.id, "port": inb.port, "email": email,
                    "kind": "клиента нет в применённом конфиге",
                    "detail": "панель выдаст по нему ссылку, но сервер его не примет",
                })
            elif live != uuid:
                report["findings"].append({
                    "inbound": inb.id, "port": inb.port, "email": email,
                    "kind": "идентификатор клиента разошёлся",
                    "panel": uuid, "applied": live,
                    "detail": "ссылка из панели работать не будет, рабочий идентификатор — из конфига",
                })
        for email in applied_clients:
            if email and email not in panel_clients:
                report["findings"].append({
                    "inbound": inb.id, "port": inb.port, "email": email,
                    "kind": "лишний клиент в применённом конфиге",
                    "detail": "в панели его нет, но доступ у него есть",
                })

        # ключи Reality: разъехавшаяся пара даёт ровно тот же симптом, что и
        # чужой UUID — сервер не узнаёт клиента и уводит хендшейк на сайт-маскировку
        if inb.security == "reality":
            applied_reality = ((entry.get("streamSettings") or {}).get("realitySettings") or {})
            for label, private, public in (
                ("панель", inb.reality.get("privateKey", ""), inb.public_key),
                ("применённый конфиг",
                 applied_reality.get("privateKey", ""),
                 ((applied_reality.get("settings") or {}).get("publicKey", ""))),
            ):
                if not private or not public:
                    continue
                derived = derive_public_key(str(private))
                if derived and derived != public:
                    report["findings"].append({
                        "inbound": inb.id, "port": inb.port,
                        "kind": f"пара ключей Reality не сходится ({label})",
                        "detail": f"из приватного ключа выводится {derived[:16]}…, а клиентам отдаётся {public[:16]}…",
                    })
            if applied_reality.get("privateKey") and inb.reality.get("privateKey") \
                    and applied_reality["privateKey"] != inb.reality["privateKey"]:
                report["findings"].append({
                    "inbound": inb.id, "port": inb.port,
                    "kind": "приватный ключ Reality разошёлся",
                    "detail": "ссылки из панели содержат публичный ключ от другой пары",
                })

    return report


def summarize(report: dict[str, Any]) -> list[str]:
    """Короткие строки для вывода в консоль."""
    if report.get("error"):
        return [f"не сверить: {report['error']}"]
    lines = []
    for f in report["findings"]:
        where = f"#{f['inbound']} порт {f['port']}"
        who = f" клиент {f['email']}" if f.get("email") else ""
        extra = ""
        if f.get("panel") and f.get("applied"):
            extra = (f": в копии инбаунда {str(f['panel'])[:8]}…, "
                     f"в таблице клиентов {str(f['applied'])[:8]}…")
        lines.append(f"{where}{who} — {f['kind']}{extra}")
    return lines
