"""Модели инбаунда и клиента 3x-ui.

Главная тонкость формата: поля settings / streamSettings / sniffing / allocate
приходят от панели как СТРОКИ с JSON внутри, а не как объекты. Если отправить
их обратно объектами, панель ответит success:true, а Xray потом не поднимется.
Здесь всё это распаковывается на чтении и запаковывается на записи.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ..util import human_bytes, human_time

# протоколы, где клиент идентифицируется паролем, а не uuid
PASSWORD_PROTOCOLS = {"trojan", "shadowsocks"}


def _loads(value: Any) -> dict:
    """settings/streamSettings могут прийти строкой, объектом или None."""
    if value is None or value == "":
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _dumps(value: Any) -> str:
    """Обратная упаковка во вложенную JSON-строку."""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


@dataclass
class ClientCfg:
    """Один клиент внутри inbound.settings.clients."""

    raw: dict = field(default_factory=dict)

    @property
    def email(self) -> str:
        return str(self.raw.get("email", "") or "")

    @property
    def uuid(self) -> str:
        return str(self.raw.get("id", "") or "")

    @property
    def password(self) -> str:
        return str(self.raw.get("password", "") or "")

    def secret(self, protocol: str) -> str:
        """Идентификатор клиента в зависимости от протокола."""
        return self.password if protocol in PASSWORD_PROTOCOLS else self.uuid

    @property
    def flow(self) -> str:
        return str(self.raw.get("flow", "") or "")

    @property
    def enable(self) -> bool:
        return bool(self.raw.get("enable", True))

    @property
    def limit_ip(self) -> int:
        return int(self.raw.get("limitIp", 0) or 0)

    @property
    def total_gb(self) -> int:
        """Лимит трафика в байтах (поле называется totalGB, но хранит байты)."""
        return int(self.raw.get("totalGB", 0) or 0)

    @property
    def expiry_time(self) -> int:
        return int(self.raw.get("expiryTime", 0) or 0)

    @property
    def sub_id(self) -> str:
        return str(self.raw.get("subId", "") or "")

    @property
    def expired(self) -> bool:
        import time

        return 0 < self.expiry_time < int(time.time() * 1000)

    def describe(self, protocol: str = "vless") -> str:
        return (
            f"{self.email or '<без email>'} secret={self.secret(protocol)[:8]}… "
            f"enable={self.enable} limit={human_bytes(self.total_gb)} до={human_time(self.expiry_time)}"
        )


@dataclass
class Inbound:
    """Инбаунд панели с распакованными вложенными настройками."""

    raw: dict = field(default_factory=dict)

    @classmethod
    def from_api(cls, data: dict) -> "Inbound":
        return cls(raw=dict(data))

    # --- плоские поля ---
    @property
    def id(self) -> int:
        return int(self.raw.get("id", 0) or 0)

    @property
    def remark(self) -> str:
        return str(self.raw.get("remark", "") or "")

    @property
    def port(self) -> int:
        return int(self.raw.get("port", 0) or 0)

    @property
    def protocol(self) -> str:
        return str(self.raw.get("protocol", "") or "")

    @property
    def enable(self) -> bool:
        return bool(self.raw.get("enable", False))

    @property
    def listen(self) -> str:
        return str(self.raw.get("listen", "") or "")

    @property
    def up(self) -> int:
        return int(self.raw.get("up", 0) or 0)

    @property
    def down(self) -> int:
        return int(self.raw.get("down", 0) or 0)

    @property
    def total(self) -> int:
        return int(self.raw.get("total", 0) or 0)

    @property
    def expiry_time(self) -> int:
        return int(self.raw.get("expiryTime", 0) or 0)

    @property
    def tag(self) -> str:
        return str(self.raw.get("tag", "") or "")

    @property
    def node_id(self) -> int:
        """Узел мультинодовой панели. 0 — инбаунд поднят на самом хосте панели."""
        return int(self.raw.get("nodeId", 0) or 0)

    @property
    def share_addr(self) -> str:
        """Явно заданный адрес для клиентских ссылок, если он переопределён."""
        return str(self.raw.get("shareAddr", "") or "")

    # --- вложенные ---
    @property
    def settings(self) -> dict:
        return _loads(self.raw.get("settings"))

    @property
    def stream(self) -> dict:
        return _loads(self.raw.get("streamSettings"))

    @property
    def sniffing(self) -> dict:
        return _loads(self.raw.get("sniffing"))

    @property
    def allocate(self) -> dict:
        return _loads(self.raw.get("allocate"))

    @property
    def clients(self) -> list[ClientCfg]:
        return [ClientCfg(raw=c) for c in (self.settings.get("clients") or []) if isinstance(c, dict)]

    def client(self, email: str) -> ClientCfg | None:
        for c in self.clients:
            if c.email == email:
                return c
        return None

    @property
    def client_stats(self) -> list[dict]:
        """Счётчики трафика клиентов приходят отдельной веткой clientStats."""
        return [c for c in (self.raw.get("clientStats") or []) if isinstance(c, dict)]

    def stat_for(self, email: str) -> dict | None:
        for st in self.client_stats:
            if st.get("email") == email:
                return st
        return None

    # --- транспорт ---
    @property
    def network(self) -> str:
        return str(self.stream.get("network", "tcp") or "tcp")

    @property
    def security(self) -> str:
        return str(self.stream.get("security", "none") or "none")

    @property
    def reality(self) -> dict:
        return self.stream.get("realitySettings") or {}

    @property
    def reality_client(self) -> dict:
        """У 3x-ui клиентская часть Reality лежит в realitySettings.settings."""
        inner = self.reality.get("settings")
        return inner if isinstance(inner, dict) else {}

    @property
    def tls(self) -> dict:
        return self.stream.get("tlsSettings") or {}

    @property
    def sni(self) -> str:
        """Имя, которое клиент должен предъявлять в SNI."""
        if self.security == "reality":
            names = self.reality.get("serverNames") or []
            return str(self.reality_client.get("serverName") or (names[0] if names else "") or "")
        if self.security in ("tls", "xtls"):
            return str(self.tls.get("serverName", "") or "")
        return ""

    @property
    def reality_dest(self) -> str:
        """Сайт-маскировка. В свежих ветках Xray поле переименовано dest -> target."""
        return str(self.reality.get("target") or self.reality.get("dest") or "")

    @property
    def mldsa65_verify(self) -> str:
        """Пост-квантовый ключ проверки Reality (Xray 25.9+). Обычно пуст."""
        return str(self.reality_client.get("mldsa65Verify", "") or "")

    @property
    def short_ids(self) -> list[str]:
        return [str(s) for s in (self.reality.get("shortIds") or [])]

    @property
    def public_key(self) -> str:
        return str(self.reality_client.get("publicKey", "") or "")

    @property
    def private_key(self) -> str:
        return str(self.reality.get("privateKey", "") or "")

    @property
    def fingerprint(self) -> str:
        if self.security == "reality":
            return str(self.reality_client.get("fingerprint", "") or "chrome")
        settings = self.tls.get("settings") or {}
        return str(settings.get("fingerprint", "") or "")

    @property
    def transport_settings(self) -> dict:
        """Настройки конкретного транспорта: wsSettings, grpcSettings и т.д."""
        key = {
            "tcp": "tcpSettings",
            "ws": "wsSettings",
            "grpc": "grpcSettings",
            "http": "httpSettings",
            "h2": "httpSettings",
            "kcp": "kcpSettings",
            "quic": "quicSettings",
            "httpupgrade": "httpupgradeSettings",
            "xhttp": "xhttpSettings",
            "splithttp": "splithttpSettings",
        }.get(self.network, "")
        value = self.stream.get(key) if key else None
        return value if isinstance(value, dict) else {}

    def summary(self) -> str:
        sec = self.security if self.security != "none" else "-"
        where = f" узел={self.node_id}" if self.node_id else ""
        return (
            f"#{self.id} {self.remark or '<без имени>'} {self.protocol}/{self.network}/{sec} "
            f"порт={self.port}{where} enable={self.enable} клиентов={len(self.clients)}"
        )

    # --- запись ---
    def to_payload(self, overrides: dict | None = None) -> dict:
        """Тело для add/update: вложенные настройки обратно в JSON-строки."""
        base = {
            "up": self.up,
            "down": self.down,
            "total": self.total,
            "remark": self.remark,
            "enable": self.enable,
            "expiryTime": self.expiry_time,
            "listen": self.listen,
            "port": self.port,
            "protocol": self.protocol,
            "settings": _dumps(self.settings),
            "streamSettings": _dumps(self.stream),
            "sniffing": _dumps(self.sniffing or {"enabled": False, "destOverride": []}),
        }
        if self.allocate:
            base["allocate"] = _dumps(self.allocate)
        if overrides:
            for key, value in overrides.items():
                base[key] = _dumps(value) if key in ("settings", "streamSettings", "sniffing", "allocate") else value
        return base


def clients_payload(clients: list[dict]) -> str:
    """settings для addClient/updateClient: строка вида {"clients":[...]}."""
    return _dumps({"clients": clients})
