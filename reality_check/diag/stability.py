"""Нагрузочная проба стабильности транспорта.

Одиночный `test` доказывает, что туннель поднимается, но не ловит «подключается,
а потом не але»: деградацию под серией запросов, обрыв закачки, провал под
конкуренцией. Здесь на один поднятый туннель приходится много запросов:

  A) серия коротких запросов подряд — доля успехов, медиана и джиттер задержки;
  B) устойчивая закачка — доходит ли транспорт до конца и с какой скоростью;
  C) пачка параллельных запросов — держит ли конкуренцию.

Транспорт, у которого падает доля успехов, рвётся закачка или скачет задержка
после подъёма, — и есть нестабильный.
"""

from __future__ import annotations

import statistics
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import requests

from ..api.links import client_config, outbound_from
from ..api.models import ClientCfg, Inbound
from ..config import Server
from ..util import TOOLS, run_dir, ts, write_json
from . import net
from .e2e import ensure_xray

SMALL_URL = "https://www.gstatic.com/generate_204"
DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes={bytes}"


def _get(proxy: str, url: str, timeout: float) -> tuple[bool, float]:
    """Один запрос через SOCKS-туннель: успех и задержка в мс."""
    start = time.perf_counter()
    try:
        requests.get(
            url,
            timeout=timeout,
            proxies={"http": proxy, "https": proxy},
            allow_redirects=False,
        )
        return True, (time.perf_counter() - start) * 1000
    except Exception:  # любой сбой запроса (в т.ч. socks) — это провал
        return False, (time.perf_counter() - start) * 1000


def stress_test(
    server: Server,
    inb: Inbound,
    client: ClientCfg,
    *,
    host: str = "",
    requests_n: int = 20,
    download_mb: float = 2.0,
    parallel_n: int = 8,
    small_timeout: float = 6.0,
    download_timeout: float = 20.0,
) -> dict[str, Any]:
    """Поднимает один туннель и гоняет по нему серию/закачку/параллель."""
    binary = ensure_xray()
    host = host or server.client_host
    port = net.free_port()

    conf = client_config(outbound_from(inb, client, host), port)
    workdir = run_dir("stress", f"{ts()}-{server.name}-{inb.id}")
    conf_path = workdir / "client-config.json"
    write_json(conf_path, conf)

    res: dict[str, Any] = {
        "server": server.name,
        "inbound": inb.id,
        "remark": inb.remark,
        "scheme": f"{inb.protocol}/{inb.network}/{inb.security}",
        "email": client.email,
        "socks_port": port,
        "artifacts": str(workdir),
    }

    proc = subprocess.Popen(
        [str(binary), "run", "-c", str(conf_path)],
        cwd=str(TOOLS),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        if not net.wait_port("127.0.0.1", port, timeout=10):
            res["error"] = "локальный Xray не открыл SOCKS-порт"
            return res
        proxy = f"socks5h://127.0.0.1:{port}"
        _get(proxy, SMALL_URL, small_timeout)  # прогрев, не считаем

        # A) серия подряд
        oks, lats = 0, []
        for _ in range(requests_n):
            ok, ms = _get(proxy, SMALL_URL, small_timeout)
            if ok:
                oks += 1
                lats.append(ms)
        res["serial_ok"] = oks
        res["serial_total"] = requests_n
        if lats:
            res["p50_ms"] = round(statistics.median(lats))
            res["p95_ms"] = round(sorted(lats)[max(0, int(len(lats) * 0.95) - 1)])
            res["jitter_ms"] = round(statistics.pstdev(lats))

        # B) устойчивая закачка
        want = int(download_mb * 1_000_000)
        url = DOWNLOAD_URL.format(bytes=want)
        got, start = 0, time.perf_counter()
        try:
            r = requests.get(
                url,
                timeout=download_timeout,
                proxies={"http": proxy, "https": proxy},
                stream=True,
            )
            for chunk in r.iter_content(65536):
                got += len(chunk)
            elapsed = time.perf_counter() - start
            res["download_ok"] = got >= want * 0.98
            if res["download_ok"] and elapsed > 0:
                res["mbps"] = round(got / elapsed / 125_000, 1)
        except Exception as e:  # обрыв закачки — искомая нестабильность
            res["download_ok"] = False
            res["download_error"] = type(e).__name__
        res["download_bytes"] = got

        # C) параллельно
        with ThreadPoolExecutor(max_workers=parallel_n) as ex:
            outs = list(
                ex.map(
                    lambda _: _get(proxy, SMALL_URL, small_timeout + 4),
                    range(parallel_n),
                )
            )
        res["parallel_ok"] = sum(1 for ok, _ in outs if ok)
        res["parallel_total"] = parallel_n

        res["stable"] = _is_stable(res)
        res["verdict"] = _verdict(res)
        return res
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        write_json(workdir / "result.json", res)


def _is_stable(res: dict[str, Any]) -> bool:
    serial_full = res.get("serial_ok") == res.get("serial_total")
    par_full = res.get("parallel_ok") == res.get("parallel_total")
    # джиттер выше медианы — соединение дёргается даже при формальном успехе
    steady = res.get("jitter_ms", 0) <= max(50, res.get("p50_ms", 0))
    return bool(serial_full and par_full and res.get("download_ok") and steady)


def _verdict(res: dict[str, Any]) -> str:
    if res.get("error"):
        return res["error"]
    if res.get("stable"):
        return "стабилен"
    reasons = []
    if res.get("serial_ok") != res.get("serial_total"):
        reasons.append(f"серия {res.get('serial_ok')}/{res.get('serial_total')}")
    if not res.get("download_ok"):
        reasons.append("закачка рвётся")
    if res.get("parallel_ok") != res.get("parallel_total"):
        reasons.append(
            f"параллель {res.get('parallel_ok')}/{res.get('parallel_total')}"
        )
    if res.get("jitter_ms", 0) > max(50, res.get("p50_ms", 0)):
        reasons.append(f"джиттер {res.get('jitter_ms')}мс")
    return "нестабилен: " + ", ".join(reasons) if reasons else "нестабилен"


def summarize_row(res: dict[str, Any]) -> list[str]:
    """Строка для сравнительной таблицы по инбаунду."""
    dl = "ok" if res.get("download_ok") else "FAIL"
    return [
        f"#{res.get('inbound')}",
        res.get("remark", ""),
        res.get("scheme", ""),
        f"{res.get('serial_ok', '-')}/{res.get('serial_total', '-')}",
        str(res.get("p50_ms", "-")),
        str(res.get("jitter_ms", "-")),
        dl,
        str(res.get("mbps", "-")),
        f"{res.get('parallel_ok', '-')}/{res.get('parallel_total', '-')}",
        res.get("verdict", ""),
    ]


ROW_HEADERS = [
    "инбаунд",
    "имя",
    "схема",
    "серия",
    "p50мс",
    "джит",
    "закач",
    "Мбит/с",
    "паралл",
    "вердикт",
]
