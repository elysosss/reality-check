"""Ноды мультинодовой панели.

Панель 3.x умеет раздавать инбаунды по узлам: инбаунд с `nodeId` физически
поднят не на хосте панели, а на отдельной ноде, и подключаться клиенты должны
к её адресу. Без этого проверки бьют не по тому хосту и дают ложный диагноз
«порт закрыт».

Состояние ноды панель отдаёт сама (status, xrayState, configDirty) — это заменяет
часть проверок уровня L2 для инбаундов, живущих на узле.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .client import XUIClient, XUIError

log = logging.getLogger(__name__)

LIST_PATHS = [
    ("GET", "/panel/api/nodes/list"),
    ("GET", "/panel/api/nodes"),
    ("GET", "/panel/api/node/list"),
]


@dataclass
class Node:
    raw: dict = field(default_factory=dict)

    @property
    def id(self) -> int:
        return int(self.raw.get("id", 0) or 0)

    @property
    def name(self) -> str:
        return str(self.raw.get("name", "") or "")

    @property
    def address(self) -> str:
        return str(self.raw.get("address", "") or "")

    @property
    def guid(self) -> str:
        return str(self.raw.get("guid", "") or "")

    @property
    def enable(self) -> bool:
        return bool(self.raw.get("enable", True))

    @property
    def status(self) -> str:
        return str(self.raw.get("status", "") or "")

    @property
    def online(self) -> bool:
        return self.status.lower() == "online"

    @property
    def xray_state(self) -> str:
        return str(self.raw.get("xrayState", "") or "")

    @property
    def xray_error(self) -> str:
        return str(self.raw.get("xrayError", "") or "")

    @property
    def last_error(self) -> str:
        return str(self.raw.get("lastError", "") or "")

    @property
    def config_dirty(self) -> bool:
        """true — нода ещё не применила последнюю версию конфига от панели."""
        return bool(self.raw.get("configDirty", False))

    @property
    def latency_ms(self) -> int | None:
        value = self.raw.get("latencyMs")
        return int(value) if isinstance(value, (int, float)) else None

    def problems(self) -> list[str]:
        """Что с нодой не так с точки зрения панели."""
        issues: list[str] = []
        if not self.enable:
            issues.append(f"нода '{self.name}' выключена в панели")
        if self.status and not self.online:
            issues.append(f"нода '{self.name}' не на связи (status={self.status})")
        if self.xray_state and self.xray_state.lower() not in ("running", "true"):
            issues.append(f"Xray на ноде '{self.name}' в состоянии '{self.xray_state}'")
        if self.xray_error:
            issues.append(f"Xray на ноде '{self.name}': {self.xray_error[:200]}")
        if self.last_error:
            issues.append(f"нода '{self.name}' сообщает об ошибке: {self.last_error[:200]}")
        if self.config_dirty:
            issues.append(
                f"нода '{self.name}' не применила последнюю версию конфига (configDirty) — "
                f"изменения из панели до неё не доехали"
            )
        return issues

    def summary(self) -> str:
        return (
            f"#{self.id} {self.name} {self.address} status={self.status or '?'} "
            f"xray={self.xray_state or '?'} {self.latency_ms if self.latency_ms is not None else '?'}мс "
            f"инбаундов={self.raw.get('inboundCount', '?')}"
        )


def list_nodes(cli: XUIClient) -> list[Node]:
    """Ноды панели. Пустой список — панель однонодовая, это не ошибка."""
    for method, path in LIST_PATHS:
        try:
            obj = cli.request(method, path)
        except XUIError:
            continue
        if isinstance(obj, list):
            return [Node(raw=n) for n in obj if isinstance(n, dict)]
    return []


def node_map(cli: XUIClient) -> dict[int, Node]:
    return {n.id: n for n in list_nodes(cli)}


def resolve_host(server: Any, inb: Any, nodes: dict[int, Node] | None = None) -> str:
    """Адрес, к которому клиенту следует подключаться для этого инбаунда.

    Приоритет: явный shareAddr в инбаунде -> адрес ноды, если инбаунд на узле ->
    public_host/адрес панели из конфига.
    """
    share = str(inb.raw.get("shareAddr", "") or "").strip()
    if share:
        return share
    node_id = inb.raw.get("nodeId")
    if node_id and nodes:
        node = nodes.get(int(node_id))
        if node and node.address:
            return node.address
    return server.client_host


def node_of(inb: Any, nodes: dict[int, Node] | None = None) -> Node | None:
    node_id = inb.raw.get("nodeId")
    if node_id and nodes:
        return nodes.get(int(node_id))
    return None
