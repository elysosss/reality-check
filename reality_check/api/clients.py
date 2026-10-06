"""Операции с клиентами внутри инбаунда: выдача доступа, лимиты, трафик, онлайн."""
from __future__ import annotations

import logging
import secrets
import time
import uuid as uuidlib
from typing import Any

from .client import XUIClient, XUIError
from .inbounds import find_inbound, new_uuid
from .models import PASSWORD_PROTOCOLS, ClientCfg, Inbound, clients_payload

log = logging.getLogger(__name__)


def build_client(
    inb: Inbound,
    email: str,
    *,
    cli: XUIClient | None = None,
    flow: str | None = None,
    limit_ip: int = 0,
    total_gb: float = 0,
    expiry_days: int = 0,
    enable: bool = True,
    sub_id: str = "",
) -> dict:
    """Формирует запись клиента, повторяя схему уже существующих в этом инбаунде.

    flow берётся у соседей по инбаунду, а не выдумывается: xtls-rprx-vision
    допустим только при tcp+reality/tls, и подставлять его вслепую нельзя.
    """
    existing = inb.clients
    if flow is None:
        flow = existing[0].flow if existing else ""
        if inb.protocol == "vless" and not flow and inb.security in ("reality", "tls") and inb.network == "tcp":
            flow = "xtls-rprx-vision"

    # за образец берём соседа по инбаунду: разные ветки панели хранят у клиента
    # разный набор полей (comment, tgId числом, created_at и т.п.), и своя выдумка
    # тут приводит к записи, которую панель принимает, а Xray не понимает
    template: dict[str, Any] = {}
    if existing:
        template = {
            k: v
            for k, v in existing[0].raw.items()
            if k not in ("id", "password", "email", "subId", "created_at", "updated_at")
        }

    entry: dict[str, Any] = {
        **template,
        "email": email,
        "enable": enable,
        "limitIp": int(limit_ip),
        "totalGB": int(total_gb * 1024 ** 3),
        "expiryTime": int((time.time() + expiry_days * 86400) * 1000) if expiry_days else 0,
        "subId": sub_id or secrets.token_hex(8),
        "reset": 0,
    }
    entry.setdefault("tgId", "")

    if inb.protocol in PASSWORD_PROTOCOLS:
        entry["password"] = secrets.token_urlsafe(16)
    else:
        entry["id"] = new_uuid(cli)
        if inb.protocol == "vless":
            entry["flow"] = flow
        elif inb.protocol == "vmess":
            entry["alterId"] = 0
            entry["security"] = "auto"

    return entry


def add_client(cli: XUIClient, inb: Inbound, entry: dict, *, apply: bool = False) -> dict[str, Any]:
    payload = {"id": inb.id, "settings": clients_payload([entry])}
    if not apply:
        return {"dry_run": True, "payload": payload, "client": entry}
    obj = cli.post_compat("/panel/api/inbounds/addClient", payload)
    return {"dry_run": False, "result": obj, "client": entry}


def update_client(
    cli: XUIClient,
    inb: Inbound,
    entry: dict,
    *,
    apply: bool = False,
    client_id: str = "",
) -> dict[str, Any]:
    """clientId в пути — uuid (vless/vmess) либо пароль (trojan/ss).

    При смене самого идентификатора в пути должен стоять прежний: панель по нему
    находит запись, а новый берёт из тела. Для этого и нужен client_id.
    """
    client_id = client_id or entry.get("id") or entry.get("password") or ""
    if not client_id:
        raise XUIError("в записи клиента нет ни id, ни password — нечего обновлять")
    payload = {"id": inb.id, "settings": clients_payload([entry])}
    if not apply:
        return {"dry_run": True, "payload": payload, "client_id": client_id}
    obj = cli.post_compat(f"/panel/api/inbounds/updateClient/{client_id}", payload)
    return {"dry_run": False, "result": obj}


def delete_client(cli: XUIClient, inb: Inbound, client: ClientCfg, *, apply: bool = False) -> dict[str, Any]:
    client_id = client.secret(inb.protocol) or client.email
    path = f"/panel/api/inbounds/{inb.id}/delClient/{client_id}"
    if not apply:
        return {"dry_run": True, "endpoint": path}
    obj = cli.post_compat(path, {})
    return {"dry_run": False, "result": obj}


def set_client_enabled(cli: XUIClient, inb: Inbound, client: ClientCfg, enabled: bool, *, apply: bool = False):
    entry = dict(client.raw)
    entry["enable"] = enabled
    return update_client(cli, inb, entry, apply=apply)


def client_traffic(cli: XUIClient, email: str) -> dict | None:
    """Отдельный эндпоинт трафика есть не во всех ветках; при его отсутствии
    данные всё равно доступны в clientStats из общего списка инбаундов."""
    try:
        obj = cli.get(f"/panel/api/inbounds/getClientTraffics/{email}", allow_fail=True)
    except XUIError:
        return None
    return obj if isinstance(obj, dict) else None


def client_ips(cli: XUIClient, email: str) -> Any:
    """Список IP, с которых заходил клиент. Пусто — значит подключений не было."""
    try:
        return cli.post_compat(f"/panel/api/inbounds/clientIps/{email}", {})
    except XUIError:
        return None


def onlines(cli: XUIClient) -> list[str]:
    """Email'ы клиентов с активными сессиями прямо сейчас."""
    from .registry import onlines as registry_onlines

    return registry_onlines(cli)


def resolve_client(cli: XUIClient, inbound_ref: str | int, email: str) -> tuple[Inbound, ClientCfg]:
    """Инбаунд и клиент, у которого идентификатор взят из таблицы клиентов панели.

    Копия клиента внутри инбаунда может быть устаревшей — по ней панель собирает
    нерабочие ссылки. Расхождение не скрываем, а проговариваем в лог.
    """
    from .registry import authoritative_client

    inb = find_inbound(cli, inbound_ref)
    client, warning = authoritative_client(cli, inb, email)
    if client is None:
        known = ", ".join(c.email for c in inb.clients) or "(клиентов нет)"
        raise XUIError(f"в инбаунде #{inb.id} нет клиента '{email}'. Есть: {known}")
    if warning:
        log.warning(warning)
    return inb, client


def random_email(prefix: str = "client") -> str:
    return f"{prefix}-{uuidlib.uuid4().hex[:6]}"
