"""Выполнение команд на сервере по SSH.

Транспорт — paramiko: доступ к серверам парольный, а системный ssh.exe не умеет
принимать пароль неинтерактивно (BatchMode его просто запрещает). Ключи при этом
тоже поддерживаются: если key/пароль не заданы, paramiko пробует агент и ~/.ssh.

Соединение на сервер открывается один раз и переиспользуется — диагностика
выполняет полтора десятка команд подряд, и переподключение на каждую заметно
удлиняло бы прогон.

По умолчанию разрешены только читающие команды. Это защита не от пользователя,
а от самой диагностики: она не должна ничего менять на сервере, пока человек
явно этого не попросил.
"""
from __future__ import annotations

import logging
import shlex
import threading
from dataclasses import dataclass
from typing import Any

import paramiko

from ..config import SSHCfg, Server

log = logging.getLogger(__name__)

# первый токен команды должен быть отсюда
READ_ONLY_BINARIES = {
    "cat", "head", "tail", "ls", "stat", "file", "wc", "grep", "egrep", "zgrep", "awk", "cut",
    "sort", "uniq", "tr", "echo", "printf", "date", "uptime", "uname", "hostname", "id", "whoami",
    "ps", "top", "free", "df", "du", "ss", "netstat", "ip", "route", "arp", "getent", "dig",
    "nslookup", "host", "ping", "traceroute", "mtr", "curl", "openssl", "systemctl", "journalctl",
    "ufw", "iptables", "ip6tables", "nft", "sysctl", "lsof", "which", "command", "test", "timeout",
    "jq", "sed", "find", "xray", "docker", "true", "env",
}

# флаги, превращающие «читающую» команду в пишущую
FORBIDDEN_FRAGMENTS = (
    ">", ">>", "rm ", "mv ", "dd ", "mkfs", "shutdown", "reboot", "kill", "sed -i", "tee ",
    "--delete", "-delete", "-exec", "chmod", "chown", "truncate", "systemctl start",
    "systemctl stop", "systemctl restart", "systemctl disable", "systemctl enable",
    "iptables -A", "iptables -D", "iptables -I", "iptables -F", "ufw allow", "ufw deny",
    "ufw delete", "sysctl -w", "docker run", "docker exec", "docker rm",
)


@dataclass
class SSHResult:
    command: str
    rc: int
    stdout: str
    stderr: str
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.error

    @property
    def out(self) -> str:
        return self.stdout.strip()

    def first_line(self) -> str:
        return self.out.splitlines()[0] if self.out else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "rc": self.rc,
            "ok": self.ok,
            "stdout": self.stdout[-4000:],
            "stderr": self.stderr[-2000:],
            "error": self.error,
        }


class SSHNotAllowed(Exception):
    """Команда не прошла проверку на «только чтение»."""


def _check_read_only(command: str) -> None:
    lowered = command.lower()
    for frag in FORBIDDEN_FRAGMENTS:
        if frag in lowered:
            raise SSHNotAllowed(
                f"команда содержит '{frag.strip()}' и меняет состояние сервера — "
                f"диагностика такое не запускает. Нужен явный запуск с allow_write=True."
            )
    for segment in _split_pipeline(command):
        tokens = shlex.split(segment)
        if not tokens:
            continue
        binary = tokens[0].rsplit("/", 1)[-1]
        if binary.startswith("$(") or binary.startswith("`"):
            raise SSHNotAllowed("подстановка команд в диагностике запрещена")
        if binary not in READ_ONLY_BINARIES:
            raise SSHNotAllowed(f"'{binary}' не входит в список читающих команд")


def _split_pipeline(command: str) -> list[str]:
    parts: list[str] = []
    buf = ""
    i = 0
    while i < len(command):
        two = command[i : i + 2]
        if two in ("&&", "||"):
            parts.append(buf)
            buf = ""
            i += 2
            continue
        if command[i] in "|;":
            parts.append(buf)
            buf = ""
            i += 1
            continue
        buf += command[i]
        i += 1
    parts.append(buf)
    return [p.strip() for p in parts if p.strip()]


# ---------------- соединения ----------------

_connections: dict[str, paramiko.SSHClient] = {}
_lock = threading.Lock()


def _connect(cfg: SSHCfg) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict[str, Any] = {
        "hostname": cfg.host,
        "port": cfg.port,
        "username": cfg.user,
        "timeout": cfg.timeout,
        "banner_timeout": cfg.timeout,
        "auth_timeout": cfg.timeout,
    }
    if cfg.password:
        kwargs["password"] = cfg.password
        # пароль задан явно — не даём paramiko молча уйти в ключи и упереться в отказ
        kwargs["look_for_keys"] = False
        kwargs["allow_agent"] = False
    if cfg.key:
        kwargs["key_filename"] = cfg.key
        kwargs["look_for_keys"] = False
    client.connect(**kwargs)
    return client


def get_connection(server: Server, *, reset: bool = False) -> paramiko.SSHClient:
    """Открытое соединение с сервером, одно на процесс."""
    cfg = server.ssh
    with _lock:
        existing = _connections.get(server.name)
        if existing is not None and not reset:
            transport = existing.get_transport()
            if transport is not None and transport.is_active():
                return existing
            _connections.pop(server.name, None)
        elif existing is not None:
            existing.close()
            _connections.pop(server.name, None)

        client = _connect(cfg)
        _connections[server.name] = client
        return client


def close_all() -> None:
    with _lock:
        for client in _connections.values():
            try:
                client.close()
            except Exception:
                pass
        _connections.clear()


def _wrap_sudo(cfg: SSHCfg, command: str) -> tuple[str, str]:
    """Для не-root оборачиваем в sudo -S; пароль уходит в stdin, а не в командную строку."""
    if not cfg.needs_sudo:
        return command, ""
    return f"sudo -S -p '' bash -lc {shlex.quote(command)}", (cfg.password + "\n" if cfg.password else "")


def run(server: Server, command: str, *, timeout: int = 25, allow_write: bool = False) -> SSHResult:
    """Выполняет команду на сервере. По умолчанию — только чтение."""
    cfg = server.ssh
    if not cfg.usable:
        return SSHResult(command, rc=-1, stdout="", stderr="", error="SSH для этого сервера не настроен")
    if not allow_write:
        try:
            _check_read_only(command)
        except SSHNotAllowed as e:
            return SSHResult(command, rc=-1, stdout="", stderr="", error=str(e))
        except ValueError as e:  # shlex не разобрал строку
            return SSHResult(command, rc=-1, stdout="", stderr="", error=f"не разобрал команду: {e}")

    payload, stdin_data = _wrap_sudo(cfg, command)

    for attempt in (1, 2):
        try:
            client = get_connection(server, reset=(attempt == 2))
            stdin, stdout, stderr = client.exec_command(payload, timeout=timeout)
            if stdin_data:
                stdin.write(stdin_data)
                stdin.flush()
            stdin.close()
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            rc = stdout.channel.recv_exit_status()
            return SSHResult(command, rc, out, err)
        except paramiko.AuthenticationException as e:
            return SSHResult(command, rc=-1, stdout="", stderr="", error=f"аутентификация не прошла: {e}")
        except (paramiko.SSHException, OSError) as e:
            if attempt == 1:
                continue  # соединение могло отвалиться — переподключаемся и повторяем
            return SSHResult(command, rc=-1, stdout="", stderr="", error=f"{type(e).__name__}: {e}")
    return SSHResult(command, rc=-1, stdout="", stderr="", error="соединение не установлено")


def check_access(server: Server) -> SSHResult:
    """Проверка, что пускают и мы понимаем, кем зашли."""
    return run(server, "id -un; uname -sr", timeout=25)


def run_many(server: Server, commands: dict[str, str], *, timeout: int = 25) -> dict[str, SSHResult]:
    return {name: run(server, cmd, timeout=timeout) for name, cmd in commands.items()}
