"""Таблица клиентов панели — источник истины об идентификаторах.

В ветке 3.x клиент существует сам по себе и прикрепляется к инбаундам, а внутри
инбаунда лежит лишь его копия. Копия может устареть: панель тогда показывает и
раздаёт через allLinks мёртвый uuid, тогда как Xray работает по значению из
таблицы клиентов. Поэтому идентификатор всегда берём отсюда, а из инбаунда —
только параметры транспорта.

Эндпоинтов может не быть на старых панелях: тогда функции возвращают None/пусто,
и вызывающий код спокойно откатывается на копию из инбаунда.
"""
from __future__ import annotations

import logging
from typing import Any

from .client import XUIClient, XUIError
from .models import ClientCfg, Inbound

log = logging.getLogger(__name__)


def get_client(cli: XUIClient, email: str) -> dict[str, Any] | None:
    """Запись клиента из таблицы панели. None — эндпоинта нет или клиент неизвестен."""
    try:
        obj = cli.get(f"/panel/api/clients/get/{email}")
    except XUIError:
        return None
    if isinstance(obj, dict):
        inner = obj.get("client")
        return inner if isinstance(inner, dict) else obj
    return None


def list_clients(cli: XUIClient) -> list[dict[str, Any]]:
    try:
        obj = cli.get("/panel/api/clients/list")
    except XUIError:
        return []
    if isinstance(obj, dict):
        obj = obj.get("clients") or obj.get("items") or []
    return [c for c in obj if isinstance(c, dict)] if isinstance(obj, list) else []


def sub_links(cli: XUIClient, sub_id: str) -> list[str]:
    """Ссылки, которые панель считает правильными для этого клиента."""
    if not sub_id:
        return []
    try:
        obj = cli.get(f"/panel/api/clients/subLinks/{sub_id}")
    except XUIError:
        return []
    return [str(x) for x in obj if isinstance(x, str)] if isinstance(obj, list) else []


def secret_of(record: dict[str, Any], protocol: str) -> str:
    """Идентификатор, которым клиент подключается: uuid либо пароль."""
    if protocol in ("trojan", "shadowsocks"):
        return str(record.get("password") or record.get("uuid") or "")
    return str(record.get("uuid") or record.get("id") or "")


def authoritative_client(cli: XUIClient, inb: Inbound, email: str) -> tuple[ClientCfg | None, str]:
    """Клиент с идентификатором из таблицы панели.

    Возвращает пару (клиент, предупреждение). Предупреждение непустое, когда копия
    внутри инбаунда разошлась с таблицей — это ровно тот случай, когда ссылка,
    собранная по инбаунду, работать не будет.
    """
    embedded = inb.client(email)
    record = get_client(cli, email)
    if record is None:
        return embedded, ""

    real = secret_of(record, inb.protocol)
    if not real:
        return embedded, ""

    if embedded is None:
        return None, f"клиента '{email}' нет в инбаунде #{inb.id}, хотя в таблице панели он есть"

    current = embedded.secret(inb.protocol)
    if current == real:
        return embedded, ""

    fixed = dict(embedded.raw)
    key = "password" if inb.protocol in ("trojan", "shadowsocks") else "id"
    fixed[key] = real
    warning = (
        f"копия клиента '{email}' в инбаунде #{inb.id} устарела: там {current[:8]}…, "
        f"в таблице панели {real[:8]}… — беру значение из таблицы, по нему и работает Xray"
    )
    return ClientCfg(raw=fixed), warning


def onlines(cli: XUIClient) -> list[str]:
    """Email'ы клиентов с активными сессиями. Путь различается между ветками."""
    for method, path in (
        ("POST", "/panel/api/clients/onlines"),
        ("POST", "/panel/api/inbounds/onlines"),
        ("GET", "/panel/api/inbounds/onlines"),
    ):
        try:
            obj = cli.request(method, path, allow_fail=True)
        except XUIError:
            continue
        if isinstance(obj, list):
            return [str(x) for x in obj]
    return []
