"""Загрузка описания серверов из config/servers.yaml."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml

from .util import CONFIG_DIR, expand_env, mask

DEFAULT_PATH = CONFIG_DIR / "servers.yaml"


class ConfigError(Exception):
    pass


@dataclass
class PanelCfg:
    url: str
    base_path: str = ""
    api_token: str = ""
    username: str = ""
    password: str = ""
    two_factor_code: str = ""
    verify_tls: bool = False
    timeout: int = 20

    @property
    def root(self) -> str:
        """Корень панели с учётом webBasePath, без хвостового слеша."""
        base = self.url.rstrip("/")
        bp = self.base_path.strip("/")
        return f"{base}/{bp}" if bp else base

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or ""

    @property
    def has_creds(self) -> bool:
        return bool(self.api_token or (self.username and self.password))


@dataclass
class SSHCfg:
    host: str = ""
    user: str = "root"
    port: int = 22
    key: str = ""
    password: str = ""
    enabled: bool = True
    timeout: int = 20

    @property
    def target(self) -> str:
        return f"{self.user}@{self.host}"

    @property
    def usable(self) -> bool:
        return bool(self.enabled and self.host)

    @property
    def needs_sudo(self) -> bool:
        """Не-root пользователю служебные команды придётся выполнять через sudo."""
        return self.user not in ("root", "")


@dataclass
class Server:
    name: str
    panel: PanelCfg
    ssh: SSHCfg = field(default_factory=SSHCfg)
    public_host: str = ""
    notes: str = ""

    @property
    def client_host(self) -> str:
        """Адрес, которым к серверу подключаются клиенты (может отличаться от адреса панели)."""
        return self.public_host or self.panel.host

    def describe(self) -> str:
        auth = "token" if self.panel.api_token else ("login" if self.panel.username else "нет кредов")
        return (
            f"{self.name}: panel={self.panel.root} auth={auth} "
            f"secret={mask(self.panel.api_token or self.panel.password)} "
            f"ssh={self.ssh.target if self.ssh.usable else '-'} client_host={self.client_host}"
        )


def _server_from_dict(raw: dict) -> Server:
    name = raw.get("name")
    if not name:
        raise ConfigError("у сервера отсутствует поле 'name'")
    panel_raw = raw.get("panel") or {}
    if not panel_raw.get("url"):
        raise ConfigError(f"[{name}] не задан panel.url")
    panel = PanelCfg(
        url=str(panel_raw["url"]).strip(),
        base_path=str(panel_raw.get("base_path", "") or ""),
        api_token=str(panel_raw.get("api_token", "") or ""),
        username=str(panel_raw.get("username", "") or ""),
        password=str(panel_raw.get("password", "") or ""),
        two_factor_code=str(panel_raw.get("two_factor_code", "") or ""),
        verify_tls=bool(panel_raw.get("verify_tls", False)),
        timeout=int(panel_raw.get("timeout", 20)),
    )
    ssh_raw = raw.get("ssh") or {}
    ssh = SSHCfg(
        host=str(ssh_raw.get("host", "") or ""),
        user=str(ssh_raw.get("user", "root") or "root"),
        port=int(ssh_raw.get("port", 22)),
        key=str(ssh_raw.get("key", "") or ""),
        password=str(ssh_raw.get("password", "") or ""),
        enabled=bool(ssh_raw.get("enabled", True)),
        timeout=int(ssh_raw.get("timeout", 20)),
    )
    return Server(
        name=str(name),
        panel=panel,
        ssh=ssh,
        public_host=str(raw.get("public_host", "") or ""),
        notes=str(raw.get("notes", "") or ""),
    )


def load_servers(path: str | Path | None = None) -> dict[str, Server]:
    p = Path(path) if path else DEFAULT_PATH
    if not p.exists():
        raise ConfigError(
            f"нет файла {p}.\n"
            f"Скопируй config/servers.example.yaml в config/servers.yaml и заполни."
        )
    data = expand_env(yaml.safe_load(p.read_text(encoding="utf-8")) or {})
    servers_raw = data.get("servers")
    if not servers_raw:
        raise ConfigError(f"{p}: пустой список 'servers'")
    servers: dict[str, Server] = {}
    for raw in servers_raw:
        srv = _server_from_dict(raw)
        if srv.name in servers:
            raise ConfigError(f"дублирующееся имя сервера: {srv.name}")
        servers[srv.name] = srv
    return servers


def select(servers: dict[str, Server], names: list[str] | None) -> list[Server]:
    """Выбор серверов по именам; пустой список или ['all'] — все."""
    if not names or names == ["all"]:
        return list(servers.values())
    out = []
    for n in names:
        if n not in servers:
            raise ConfigError(f"неизвестный сервер '{n}'. Доступны: {', '.join(servers)}")
        out.append(servers[n])
    return out
