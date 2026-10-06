"""Проверки на самом сервере по SSH.

Важная особенность 3x-ui: Xray там не отдельный systemd-юнит, а дочерний процесс
службы x-ui. Поэтому «systemctl status xray» на таком сервере ничего не покажет,
и смотреть надо на x-ui, на процесс xray и на его конфиг в /usr/local/x-ui/bin.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

from ..config import Server
from .ssh import SSHResult, run

XUI_BIN_DIR = "/usr/local/x-ui/bin"
XUI_CONFIG = f"{XUI_BIN_DIR}/config.json"


def facts(server: Server) -> dict[str, Any]:
    """Базовое: кто мы на сервере, что за система, не уехали ли часы."""
    r = run(server, "uname -sr; uptime -p; date -u +%s")
    out: dict[str, Any] = {"ok": r.ok, "raw": r.to_dict()}
    if r.ok:
        lines = r.out.splitlines()
        out["kernel"] = lines[0] if lines else ""
        out["uptime"] = lines[1] if len(lines) > 1 else ""
        if len(lines) > 2 and lines[2].strip().isdigit():
            skew = int(time.time()) - int(lines[2].strip())
            out["clock_skew_sec"] = skew
            if abs(skew) > 120:
                out["clock_warning"] = (
                    f"часы сервера разошлись с локальными на {skew} с — для VMess это ломает аутентификацию"
                )
    return out


def service_state(server: Server) -> dict[str, Any]:
    """Состояние панели x-ui и её журнал. Заодно смотрим отдельный юнит xray, если он есть."""
    out: dict[str, Any] = {}
    active = run(server, "systemctl is-active x-ui")
    out["x-ui_active"] = active.first_line() or active.stderr.strip()
    out["ok"] = out["x-ui_active"] == "active"

    status = run(server, "systemctl status x-ui --no-pager -n 15")
    out["status_tail"] = status.out[-2000:]

    journal = run(server, "journalctl -u x-ui -n 60 --no-pager")
    out["journal_tail"] = journal.out[-4000:]
    out["journal_errors"] = _grep_errors(journal.out)

    standalone = run(server, "systemctl is-active xray")
    state = standalone.first_line()
    if state and state != "inactive":
        out["xray_unit_active"] = state
    return out


def xray_process(server: Server) -> dict[str, Any]:
    """Живой ли процесс xray и какой версии."""
    out: dict[str, Any] = {}
    ps = run(server, "ps -eo pid,etimes,comm,args | grep -i xray | grep -v grep")
    out["running"] = bool(ps.out)
    out["ps"] = ps.out[-1500:]
    out["ok"] = out["running"]

    if ps.out:
        m = re.search(r"^\s*(\d+)\s+(\d+)\s", ps.out.splitlines()[0])
        if m:
            out["pid"] = int(m.group(1))
            out["uptime_sec"] = int(m.group(2))
            if out["uptime_sec"] < 120:
                out["note"] = (
                    f"процесс поднят {out['uptime_sec']} с назад — похоже, xray перезапускается по кругу"
                )

    ver = run(server, f"ls {XUI_BIN_DIR} | grep -E '^xray' | head -1")
    binary = ver.first_line()
    if binary:
        out["binary"] = f"{XUI_BIN_DIR}/{binary}"
        v = run(server, f"{XUI_BIN_DIR}/{binary} version | head -2")
        out["version"] = v.out
    return out


def xray_config(server: Server) -> dict[str, Any]:
    """Конфиг, который реально применён на сервере, а не то, что показывает панель."""
    out: dict[str, Any] = {}
    r = run(server, f"cat {XUI_CONFIG}", timeout=30)
    if not r.ok:
        out["ok"] = False
        out["error"] = r.stderr.strip() or r.error or "конфиг не прочитался"
        return out
    try:
        conf = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        out["ok"] = False
        out["error"] = f"конфиг на сервере не является валидным JSON: {e}"
        out["hint"] = "именно поэтому Xray и не поднимается — панель записала битый конфиг"
        return out

    out["ok"] = True
    out["config"] = conf
    out["inbound_ports"] = [i.get("port") for i in conf.get("inbounds", []) if isinstance(i, dict)]
    out["inbound_tags"] = [i.get("tag") for i in conf.get("inbounds", []) if isinstance(i, dict)]
    log_conf = conf.get("log") or {}
    out["log_paths"] = {
        "access": log_conf.get("access", ""),
        "error": log_conf.get("error", ""),
        "loglevel": log_conf.get("loglevel", ""),
    }
    routing_rules = (conf.get("routing") or {}).get("rules") or []
    out["routing_rule_count"] = len(routing_rules)
    blocked = [r for r in routing_rules if str(r.get("outboundTag", "")).lower() in ("blocked", "block")]
    out["blocking_rules"] = blocked[:10]
    return out


def xray_logs(server: Server, *, lines: int = 80, log_path: str = "") -> dict[str, Any]:
    """Хвост error-лога Xray. Путь берём из конфига, иначе пробуем обычные места."""
    candidates = [p for p in (log_path, f"{XUI_BIN_DIR}/error.log", "/usr/local/x-ui/error.log", "/var/log/xray/error.log") if p]
    out: dict[str, Any] = {"checked": candidates}
    for path in candidates:
        if path in ("none", "stdout", "stderr", ""):
            continue
        r = run(server, f"test -f {path} && tail -n {lines} {path}")
        if r.ok and r.out:
            out["ok"] = True
            out["path"] = path
            out["tail"] = r.out[-4000:]
            out["errors"] = _grep_errors(r.out)
            return out
    out["ok"] = False
    out["note"] = "файл error.log не найден — Xray под x-ui часто пишет в журнал службы, смотри journal_tail"
    return out


def listening(server: Server, port: int | None = None) -> dict[str, Any]:
    """Кто слушает порты. Сравнение с внешней пробой локализует фаервол."""
    r = run(server, "ss -tlnp")
    out: dict[str, Any] = {"ok": r.ok, "raw": r.out[-4000:]}
    if not r.ok:
        out["error"] = r.stderr.strip() or r.error
        return out
    ports: set[int] = set()
    for line in r.out.splitlines()[1:]:
        m = re.search(r":(\d+)\s", line)
        if m:
            ports.add(int(m.group(1)))
    out["ports"] = sorted(ports)
    if port is not None:
        out["port_listening"] = port in ports
        rows = [ln for ln in r.out.splitlines() if f":{port} " in ln or f":{port}\t" in ln]
        out["port_rows"] = rows
        out["bound_to_localhost"] = bool(rows) and all(
            ("127.0.0.1" in ln or "[::1]" in ln) for ln in rows
        )
    return out


def firewall(server: Server) -> dict[str, Any]:
    """Правила фильтрации на самом хосте. Молчание здесь не исключает облачный firewall."""
    out: dict[str, Any] = {}
    ufw = run(server, "ufw status verbose")
    if ufw.ok and ufw.out:
        out["ufw"] = ufw.out[-2000:]
        out["ufw_active"] = "Status: active" in ufw.out
    ipt = run(server, "iptables -S")
    if ipt.ok:
        out["iptables"] = ipt.out[-3000:]
        out["iptables_drop_policy"] = "-P INPUT DROP" in ipt.out
    nft = run(server, "nft list ruleset | head -60")
    if nft.ok and nft.out:
        out["nft"] = nft.out[-2000:]
    out["ok"] = True
    return out


def egress(server: Server) -> dict[str, Any]:
    """Ходит ли сам сервер в интернет: DNS, HTTPS, внешний IP."""
    out: dict[str, Any] = {}
    dns = run(server, "getent hosts www.google.com")
    out["dns_ok"] = dns.ok and bool(dns.out)
    out["dns_raw"] = dns.out[:200]

    http = run(server, "curl -s -m 8 -o /dev/null -w '%{http_code}' https://www.gstatic.com/generate_204")
    out["http_code"] = http.first_line()
    out["http_ok"] = out["http_code"] == "204"

    ip = run(server, "curl -s -m 8 https://api.ipify.org")
    out["external_ip"] = ip.first_line()

    out["ok"] = bool(out["dns_ok"] and out["http_ok"])
    if not out["dns_ok"]:
        out["hint"] = "сервер не резолвит имена — обычно сломан /etc/resolv.conf или DNS в конфиге Xray"
    elif not out["http_ok"]:
        out["hint"] = "DNS работает, но HTTPS наружу не идёт — блокировка исходящего трафика у провайдера"
    return out


def check_dest(server: Server, dest: str) -> dict[str, Any]:
    """Доступен ли с сервера сайт-маскировка Reality. Если нет — Reality молча не работает."""
    out: dict[str, Any] = {"dest": dest}
    if not dest:
        out["ok"] = False
        out["error"] = "dest не задан в инбаунде"
        return out
    host, _, port = dest.partition(":")
    port = port or "443"
    # без перенаправлений в шелле: их запрещает фильтр читающих команд, а stderr
    # у нас и так приходит отдельным потоком — склеиваем уже здесь
    r = run(
        server,
        f"timeout 8 openssl s_client -connect {host}:{port} -servername {host} -brief",
        timeout=25,
    )
    text = (r.stdout or "") + chr(10) + (r.stderr or "")
    out["raw"] = text[-1500:]

    if r.error:
        # проверку не удалось выполнить — это не то же самое, что недоступный dest
        out["ok"] = None
        out["error"] = r.error
        out["hint"] = "проверить dest с сервера не вышло, судить о его доступности нельзя"
        return out
    if "command not found" in text or "not found" in (r.stderr or ""):
        out["ok"] = None
        out["hint"] = "на сервере нет openssl — доступность dest не проверить"
        return out

    подключился = any(m in text for m in ("CONNECTION ESTABLISHED", "CONNECTED", "Connecting to"))
    рукопожатие = any(m in text for m in ("Verification", "subject=", "Protocol version", "Ciphersuite"))
    out["ok"] = bool(подключился and рукопожатие)
    if not out["ok"]:
        out["hint"] = (
            f"сервер не может установить TLS с {dest} — Reality не сможет проксировать хендшейк, "
            f"выбери другой dest или проверь исходящий доступ"
        )
    if "TLSv1.3" in text:
        out["tls13"] = True
    elif "CONNECTED" in text:
        out["tls13"] = False
        out["hint_tls13"] = "dest не отдаёт TLS 1.3 — для Reality это обязательное требование"
    return out


def x25519_matches(server: Server, private_key: str, public_key: str) -> dict[str, Any]:
    """Сверяет, что публичный ключ в ссылке действительно выведен из приватного на сервере."""
    out: dict[str, Any] = {"ok": None}
    if not private_key or not public_key:
        out["note"] = "нет пары ключей для сверки"
        return out
    binary = run(server, f"ls {XUI_BIN_DIR} | grep -E '^xray' | head -1").first_line()
    if not binary:
        out["note"] = "не нашли бинарь xray на сервере"
        return out
    r = run(server, f"{XUI_BIN_DIR}/{binary} x25519 -i {private_key}", timeout=20)
    if not r.ok:
        out["note"] = f"xray x25519 не отработал: {r.stderr.strip()[:200]}"
        return out
    m = re.search(r"[Pp]ublic key:\s*(\S+)", r.out)
    derived = m.group(1) if m else ""
    out["derived_public_key"] = derived
    out["ok"] = bool(derived) and derived == public_key
    if derived and derived != public_key:
        out["hint"] = (
            "публичный ключ в конфиге клиента не соответствует приватному ключу на сервере — "
            "ссылку надо перевыпустить"
        )
    return out


def _grep_errors(text: str) -> list[str]:
    pattern = re.compile(r"(error|failed|fatal|panic|invalid|rejected|refused)", re.I)
    return [ln.strip() for ln in text.splitlines() if pattern.search(ln)][-15:]


def collect(server: Server, *, port: int | None = None) -> dict[str, Any]:
    """Полный снимок состояния хоста — используется триажем."""
    return {
        "facts": facts(server),
        "service": service_state(server),
        "process": xray_process(server),
        "listening": listening(server, port),
        "firewall": firewall(server),
        "egress": egress(server),
    }


def result_dict(r: SSHResult) -> dict[str, Any]:
    return r.to_dict()
