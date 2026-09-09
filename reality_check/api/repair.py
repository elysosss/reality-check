"""Приведение базы панели в соответствие с тем, что реально работает в Xray.

Направление правки выбрано осознанно: рабочим считается идентификатор из
применённого конфига, потому что именно по нему сейчас ходят живые пользователи.
Обратный вариант (заставить Xray принять базу панели) сломал бы всем действующие
ссылки, поэтому здесь он не реализован.

Ничего не отправляет без apply=True.
"""
from __future__ import annotations

from typing import Any

from ..diag import drift
from . import registry
from .client import XUIClient, XUIError
from .models import Inbound


def plan_uuid_alignment(cli: XUIClient, inbounds: list[Inbound]) -> list[dict[str, Any]]:
    """Список правок: кому и на какой идентификатор менять."""
    by_id = {i.id: i for i in inbounds}
    report = drift.compare(cli, inbounds)
    if report.get("error"):
        raise XUIError(report["error"])

    plan: list[dict[str, Any]] = []
    for finding in report["findings"]:
        if finding["kind"] != "копия клиента в инбаунде устарела":
            continue
        inb = by_id.get(finding["inbound"])
        if inb is None:
            continue
        client = inb.client(finding["email"])
        if client is None:
            continue
        plan.append({
            "inbound_id": inb.id,
            "port": finding["port"],
            "remark": inb.remark,
            "email": finding["email"],
            "from": finding["panel"],
            "to": finding["applied"],
        })
    return plan


def describe(plan: list[dict[str, Any]]) -> list[str]:
    return [
        f"#{p['inbound_id']} порт {p['port']} {p['email']}: "
        f"{str(p['from'])[:8]}… -> {str(p['to'])[:8]}…"
        for p in plan
    ]


def apply_uuid_alignment(
    cli: XUIClient,
    inbounds: list[Inbound],
    plan: list[dict[str, Any]],
    *,
    apply: bool = False,
    limit: int = 0,
) -> list[dict[str, Any]]:
    """Просит панель заново разослать запись клиента по инбаундам.

    Идентификатор при этом не меняется: в таблице клиентов уже лежит верное
    значение, устарели только копии внутри инбаундов. Поэтому сохранение клиента
    его же собственными данными — самая безобидная операция из возможных:
    у живых пользователей ничего не отваливается.
    """
    results: list[dict[str, Any]] = []
    todo = plan[:limit] if limit else plan
    # правка на клиента, а не на инбаунд: панель разошлёт её во все привязанные
    seen: set[str] = set()
    for step in todo:
        email = step["email"]
        if email in seen:
            continue
        seen.add(email)
        record = registry.get_client(cli, email)
        if record is None:
            results.append({**step, "error": "клиента нет в таблице панели"})
            continue
        if not apply:
            results.append({**step, "dry_run": True})
            continue
        try:
            obj = cli.post_compat(f"/panel/api/clients/update/{email}", record)
            results.append({**step, "dry_run": False, "result": obj})
        except XUIError as e:
            results.append({**step, "error": e.message})
    return results
