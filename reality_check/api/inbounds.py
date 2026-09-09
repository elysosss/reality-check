"""Операции с инбаундами: чтение, клонирование известно-рабочей схемы, запись.

Все изменяющие функции принимают apply=False и по умолчанию только показывают,
что было бы отправлено. Перед update/del вызывающий код обязан сохранить снапшот.
"""
from __future__ import annotations

import copy
import logging
import uuid as uuidlib
from typing import Any

from . import server
from .client import XUIClient, XUIError
from .models import Inbound

log = logging.getLogger(__name__)


def list_inbounds(cli: XUIClient) -> list[Inbound]:
    obj = cli.get("/panel/api/inbounds/list") or []
    return [Inbound.from_api(item) for item in obj if isinstance(item, dict)]


def get_inbound(cli: XUIClient, inbound_id: int) -> Inbound:
    obj = cli.get(f"/panel/api/inbounds/get/{inbound_id}")
    if not isinstance(obj, dict):
        raise XUIError(f"инбаунд {inbound_id} не найден", endpoint=f"GET /panel/api/inbounds/get/{inbound_id}")
    return Inbound.from_api(obj)


def find_inbound(cli: XUIClient, ref: str | int) -> Inbound:
    """Инбаунд по id или по remark — в командах удобнее ссылаться на имя."""
    inbounds = list_inbounds(cli)
    ref_str = str(ref)
    if ref_str.isdigit():
        wanted = int(ref_str)
        for inb in inbounds:
            if inb.id == wanted:
                return inb
        raise XUIError(f"инбаунд с id={wanted} не найден на {cli.server.name}")
    matches = [inb for inb in inbounds if inb.remark == ref_str]
    if not matches:
        matches = [inb for inb in inbounds if ref_str.lower() in inb.remark.lower()]
    if not matches:
        known = ", ".join(f"#{i.id}:{i.remark}" for i in inbounds) or "(нет инбаундов)"
        raise XUIError(f"инбаунд '{ref_str}' не найден на {cli.server.name}. Есть: {known}")
    if len(matches) > 1:
        names = ", ".join(f"#{i.id}:{i.remark}" for i in matches)
        raise XUIError(f"'{ref_str}' подходит нескольким инбаундам: {names} — уточни id")
    return matches[0]


def new_uuid(cli: XUIClient | None = None) -> str:
    """UUID для клиента: сперва просим панель (её версия — источник истины), иначе локально."""
    if cli is not None:
        try:
            value = server.new_uuid(cli)
            if value:
                return value
        except XUIError:
            pass
    return str(uuidlib.uuid4())


def new_reality_keys(cli: XUIClient) -> dict[str, str]:
    """Свежая пара ключей x25519 для Reality. Приватный ключ никуда не логируем."""
    return server.new_x25519(cli)


def add_inbound(cli: XUIClient, payload: dict, *, apply: bool = False) -> dict[str, Any]:
    """Создаёт инбаунд. Без apply=True только возвращает то, что было бы отправлено."""
    if not apply:
        return {"dry_run": True, "payload": payload}
    obj = cli.post_compat("/panel/api/inbounds/add", payload)
    return {"dry_run": False, "result": obj}


def update_inbound(cli: XUIClient, inbound_id: int, payload: dict, *, apply: bool = False) -> dict[str, Any]:
    if not apply:
        return {"dry_run": True, "payload": payload}
    obj = cli.post_compat(f"/panel/api/inbounds/update/{inbound_id}", payload)
    return {"dry_run": False, "result": obj}


def delete_inbound(cli: XUIClient, inbound_id: int, *, apply: bool = False) -> dict[str, Any]:
    if not apply:
        return {"dry_run": True, "inbound_id": inbound_id}
    obj = cli.post_compat(f"/panel/api/inbounds/del/{inbound_id}", {})
    return {"dry_run": False, "result": obj}


def clone_payload(
    source: Inbound,
    *,
    port: int,
    remark: str,
    cli: XUIClient | None = None,
    fresh_reality: bool = True,
    keep_clients: bool = False,
) -> dict:
    """Тело нового инбаунда по образцу уже работающего.

    Копируется вся схема транспорта; заменяются только те поля, которые обязаны
    быть уникальными: порт, имя, секреты клиентов и — для Reality — пара ключей
    и shortId. Так новый инбаунд повторяет заведомо рабочую конфигурацию.
    """
    stream = copy.deepcopy(source.stream)
    settings = copy.deepcopy(source.settings)

    if source.security == "reality" and fresh_reality:
        reality = stream.get("realitySettings") or {}
        if cli is not None:
            keys = new_reality_keys(cli)
            reality["privateKey"] = keys["privateKey"]
            inner = reality.get("settings") or {}
            inner["publicKey"] = keys["publicKey"]
            reality["settings"] = inner
        reality["shortIds"] = [uuidlib.uuid4().hex[:8]]
        stream["realitySettings"] = reality

    clients = settings.get("clients")
    if isinstance(clients, list):
        if keep_clients:
            for c in clients:
                if "id" in c:
                    c["id"] = str(uuidlib.uuid4())
                if "password" in c:
                    c["password"] = uuidlib.uuid4().hex[:16]
                if c.get("email"):
                    c["email"] = f"{c['email']}-{port}"
        else:
            settings["clients"] = []

    return Inbound(
        raw={
            **source.raw,
            "id": 0,
            "up": 0,
            "down": 0,
            "remark": remark,
            "port": port,
            "settings": settings,
            "streamSettings": stream,
            "clientStats": [],
        }
    ).to_payload()


def set_inbound_enabled(
    cli: XUIClient, inbound_id: int, enabled: bool, *, apply: bool = False
) -> dict[str, Any]:
    """Переключает только флаг enable, не пересобирая настройки инбаунда.

    Выключенный инбаунд не попадает в конфиг Xray — это штатный способ убрать
    сломанный инбаунд, из-за которого не стартует весь конфиг, ничего при этом
    не удаляя.
    """
    path = f"/panel/api/inbounds/setEnable/{inbound_id}"
    body = {"enable": enabled}
    if not apply:
        return {"dry_run": True, "endpoint": path, "body": body}
    obj = cli.post_compat(path, body)
    return {"dry_run": False, "result": obj}
