"""Честная проверка конфига: поднимаем локальный Xray-клиент и реально ходим через него.

Всё остальное в этом проекте — косвенные признаки. Работоспособность доказывает
только успешный запрос через SOCKS5-порт локального клиента и совпадение
внешнего IP с адресом сервера.
"""
from __future__ import annotations

import io
import json
import platform
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any

import requests

from ..api.links import client_config, outbound_from
from ..api.models import ClientCfg, Inbound
from ..config import Server
from ..util import TOOLS, run_dir, ts, write_json
from . import net

XRAY_RELEASE_URL = "https://github.com/XTLS/Xray-core/releases/latest/download/{asset}"
IP_ECHO_URLS = ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"]
CONNECTIVITY_URL = "https://www.gstatic.com/generate_204"


class XrayMissing(Exception):
    pass


def _asset_name() -> str:
    machine = platform.machine().lower()
    if platform.system() == "Windows":
        return "Xray-windows-arm64-v8a.zip" if "arm" in machine else "Xray-windows-64.zip"
    if platform.system() == "Darwin":
        return "Xray-macos-arm64-v8a.zip" if "arm" in machine else "Xray-macos-64.zip"
    return "Xray-linux-arm64-v8a.zip" if "arm" in machine else "Xray-linux-64.zip"


def xray_path() -> Path:
    return TOOLS / ("xray.exe" if platform.system() == "Windows" else "xray")


def ensure_xray() -> Path:
    path = xray_path()
    if not path.exists():
        raise XrayMissing(
            f"нет локального xray-core ({path}).\n"
            f"Скачай его один раз командой:  python -m reality_check fetch-xray"
        )
    return path


def fetch_xray(*, force: bool = False) -> dict[str, Any]:
    """Разовая загрузка официального релиза Xray-core в tools/."""
    path = xray_path()
    if path.exists() and not force:
        return {"downloaded": False, "path": str(path), "note": "уже есть, скачивание не требуется"}

    asset = _asset_name()
    url = XRAY_RELEASE_URL.format(asset=asset)
    TOOLS.mkdir(parents=True, exist_ok=True)
    r = requests.get(url, timeout=180, allow_redirects=True)
    r.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        names = zf.namelist()
        wanted = [n for n in names if n.rsplit("/", 1)[-1] in ("xray.exe", "xray")]
        if not wanted:
            raise RuntimeError(f"в архиве {asset} нет бинаря xray: {names[:10]}")
        with zf.open(wanted[0]) as src:
            path.write_bytes(src.read())
        for extra in ("geoip.dat", "geosite.dat"):
            if extra in names:
                (TOOLS / extra).write_bytes(zf.read(extra))
    if platform.system() != "Windows":
        path.chmod(0o755)
    return {"downloaded": True, "path": str(path), "asset": asset, "size": path.stat().st_size}


def test_config(
    server: Server,
    inb: Inbound,
    client: ClientCfg,
    *,
    host: str = "",
    timeout: float = 20.0,
    keep_artifacts: bool = True,
    log_level: str = "warning",
) -> dict[str, Any]:
    """Поднимает клиент, делает два запроса через него и гасит процесс.

    log_level='debug' включает подробный лог Xray — при разборе провала именно
    там видно, на чём именно рвётся соединение.
    """
    binary = ensure_xray()
    host = host or server.client_host
    port = net.free_port()

    outbound = outbound_from(inb, client, host)
    conf = client_config(outbound, port, log_level=log_level)

    workdir = run_dir("tests", f"{ts()}-{server.name}-{inb.id}-{client.email or 'noemail'}")
    conf_path = workdir / "client-config.json"
    write_json(conf_path, conf)

    result: dict[str, Any] = {
        "server": server.name,
        "inbound": inb.id,
        "remark": inb.remark,
        "email": client.email,
        "host": host,
        "port": inb.port,
        "protocol": inb.protocol,
        "network": inb.network,
        "security": inb.security,
        "socks_port": port,
        "artifacts": str(workdir),
        "passed": False,
    }

    proc = subprocess.Popen(
        [str(binary), "run", "-c", str(conf_path)],
        cwd=str(TOOLS),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        if not net.wait_port("127.0.0.1", port, timeout=10):
            result["error"] = "локальный Xray не открыл SOCKS-порт"
            result["stage"] = "startup"
            return _finish(proc, workdir, result)

        proxy = f"socks5h://127.0.0.1:{port}"

        connectivity = net.http_probe(CONNECTIVITY_URL, timeout=timeout, proxy=proxy)
        result["connectivity"] = connectivity

        exit_ip = ""
        ip_probe: dict[str, Any] = {}
        # если базовый запрос не прошёл, туннель мёртв и опрос IP-эхо только
        # утроит время падающего теста — смысла в нём нет
        if connectivity.get("ok"):
            for url in IP_ECHO_URLS:
                ip_probe = net.http_probe(url, timeout=timeout, proxy=proxy)
                if ip_probe.get("ok"):
                    exit_ip = (ip_probe.get("body") or "").strip()
                    break
        result["exit_ip_probe"] = ip_probe
        result["exit_ip"] = exit_ip

        expected = net.resolve(host).get("addresses") or []
        result["server_addresses"] = expected
        result["exit_ip_matches_server"] = bool(exit_ip and exit_ip in expected)

        tunnel_up = bool(connectivity.get("ok") and connectivity.get("status") in (204, 200))
        result["passed"] = bool(tunnel_up and exit_ip)
        if result["passed"] and not result["exit_ip_matches_server"]:
            result["warning"] = (
                f"трафик проходит, но выходной IP {exit_ip} не совпадает с адресом сервера {expected} — "
                f"либо у сервера другой исходящий адрес, либо трафик уходит мимо туннеля"
            )
        if not result["passed"]:
            result["stage"] = "traffic"
        return _finish(proc, workdir, result)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if not keep_artifacts:
            try:
                conf_path.unlink(missing_ok=True)
            except OSError:
                pass


def _finish(proc: subprocess.Popen, workdir: Path, result: dict[str, Any]) -> dict[str, Any]:
    if proc.poll() is None:
        proc.terminate()
    try:
        output = proc.communicate(timeout=5)[0] or ""
    except subprocess.TimeoutExpired:
        proc.kill()
        output = proc.communicate()[0] or ""
    (workdir / "xray.log").write_text(output, encoding="utf-8")
    result["xray_log_tail"] = output.strip().splitlines()[-15:]
    result["xray_exit_code"] = proc.returncode
    if proc.returncode not in (0, None) and not result.get("passed"):
        result.setdefault("stage", "startup")
        result["hint"] = "локальный Xray завершился с ошибкой — смотри xray.log в артефактах"
    write_json(workdir / "result.json", result)
    return result


def summarize(result: dict[str, Any]) -> str:
    verdict = "PASS" if result.get("passed") else "FAIL"
    head = (
        f"{verdict}  {result.get('server')} #{result.get('inbound')} "
        f"({result.get('protocol')}/{result.get('network')}/{result.get('security')}) "
        f"клиент={result.get('email')}"
    )
    lines = [head]
    conn = result.get("connectivity") or {}
    if conn:
        lines.append(
            f"  проходимость: {'ok' if conn.get('ok') else 'нет'} "
            f"{conn.get('status', conn.get('error', ''))} за {conn.get('ms', '?')} мс"
        )
    if result.get("exit_ip"):
        match = "совпадает с сервером" if result.get("exit_ip_matches_server") else "НЕ совпадает с сервером"
        lines.append(f"  внешний IP: {result['exit_ip']} ({match})")
    for key in ("error", "warning", "hint"):
        if result.get(key):
            lines.append(f"  {key}: {result[key]}")
    if not result.get("passed") and result.get("xray_log_tail"):
        lines.append("  лог xray:")
        lines.extend(f"    {ln}" for ln in result["xray_log_tail"][-5:])
    lines.append(f"  артефакты: {result.get('artifacts')}")
    return "\n".join(lines)
