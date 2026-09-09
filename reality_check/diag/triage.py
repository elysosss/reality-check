"""Послойная локализация поломки.

Диагностика идёт сверху вниз и на каждом слое по возможности сравнивает взгляд
снаружи со взглядом с самого сервера. Именно расхождение между ними и указывает
на виновника: «слушает изнутри, но снаружи не достучаться» — это фильтрация,
а не сломанный Xray.

Ничего не чинит. На выходе — факты по слоям, первый провалившийся слой и
ранжированные гипотезы.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ..api import server as server_api
from ..api.client import AuthError, XUIClient, XUIError
from ..api.clients import client_ips, onlines
from ..api.inbounds import find_inbound, list_inbounds
from ..api.models import ClientCfg, Inbound
from ..api.nodes import Node, node_map, node_of, resolve_host
from ..config import Server
from ..util import human_bytes, human_time, run_dir, ts, write_json
from . import drift, e2e, host, net
from .ssh import check_access


@dataclass
class Layer:
    code: str
    title: str
    ok: bool | None = None  # None — проверить не удалось или неприменимо
    facts: dict[str, Any] = field(default_factory=dict)
    verdict: str = ""
    hints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "title": self.title,
            "ok": self.ok,
            "verdict": self.verdict,
            "hints": self.hints,
            "facts": self.facts,
        }


def diagnose(
    server: Server,
    *,
    inbound_ref: str | int | None = None,
    email: str | None = None,
    use_ssh: bool = True,
    run_e2e: bool = True,
) -> dict[str, Any]:
    layers: list[Layer] = []
    ctx: dict[str, Any] = {}

    cli: XUIClient | None = None
    inb: Inbound | None = None
    client: ClientCfg | None = None
    node_by_id: dict[int, Node] = {}
    node: Node | None = None
    target_host: str = server.client_host

    # ---------- L0: панель ----------
    l0 = Layer("L0", "панель 3x-ui доступна и пускает")
    panel_host = server.panel.host
    panel_port = urlparse(server.panel.url).port or (443 if server.panel.url.startswith("https") else 80)
    l0.facts["tcp"] = net.tcp_connect(panel_host, panel_port)
    try:
        cli = XUIClient(server)
        l0.facts["auth_mode"] = cli.ensure_auth()
        l0.ok = True
        l0.verdict = f"панель отвечает, авторизация: {l0.facts['auth_mode']}"
    except AuthError as e:
        l0.ok = False
        l0.verdict = "не удалось авторизоваться в панели"
        l0.hints.append(e.message)
        l0.hints.append("проверь api_token/логин и base_path в config/servers.yaml")
    except Exception as e:
        l0.ok = False
        l0.verdict = f"панель недоступна: {type(e).__name__}: {e}"
        l0.hints.append("если TCP тоже не проходит — панель лежит либо сменился порт")
    layers.append(l0)

    # ---------- L1: логика в панели ----------
    l1 = Layer("L1", "инбаунд и клиент в панели в рабочем состоянии")
    if cli is not None and l0.ok:
        try:
            inbounds = list_inbounds(cli)
            l1.facts["inbound_count"] = len(inbounds)

            # инбаунд может быть поднят не на хосте панели, а на узле: тогда и
            # проверять достижимость надо по адресу узла, иначе диагноз ложный
            node_by_id = node_map(cli)
            if node_by_id:
                l1.facts["nodes"] = [n.summary() for n in node_by_id.values()]

            # два включённых инбаунда на одном порту физически не уживаются —
            # но только в пределах одного хоста: одинаковый порт на разных узлах
            # это нормально, поэтому группируем по паре (узел, порт)
            ports: dict[tuple[int, int], list[int]] = {}
            for other in inbounds:
                if other.enable and not other.listen:
                    ports.setdefault((other.node_id, other.port), []).append(other.id)
            conflicts = {key: ids for key, ids in ports.items() if len(ids) > 1}
            if conflicts:
                l1.facts["port_conflicts"] = {f"узел{k[0]}:{k[1]}": v for k, v in conflicts.items()}
                l1.hints.append(
                    "конфликт портов на одном хосте: "
                    + "; ".join(
                        f"порт {port} занимают #{', #'.join(map(str, ids))}"
                        for (_, port), ids in conflicts.items()
                    )
                )
            if inbound_ref is not None:
                inb = find_inbound(cli, inbound_ref)
            elif len(inbounds) == 1:
                inb = inbounds[0]
            if inb is None:
                l1.ok = None
                l1.verdict = "конкретный инбаунд не задан — проверяю только уровень панели"
                l1.facts["inbounds"] = [i.summary() for i in inbounds]
            else:
                l1.facts["inbound"] = inb.summary()
                node = node_of(inb, node_by_id)
                target_host = resolve_host(server, inb, node_by_id)
                l1.facts["target_host"] = target_host
                if node is not None:
                    l1.facts["node"] = node.summary()
                problems: list[str] = []
                if not inb.enable:
                    problems.append(f"инбаунд #{inb.id} выключен в панели")
                same_host = conflicts.get((inb.node_id, inb.port)) or []
                if inb.id in same_host:
                    problems.append(
                        f"порт {inb.port} на одном хосте делят включённые инбаунды #"
                        + ", #".join(str(i) for i in same_host)
                        + " — работать будет только один из них"
                    )
                if inb.total and (inb.up + inb.down) >= inb.total:
                    problems.append("инбаунд выбрал лимит трафика")
                if 0 < inb.expiry_time < int(time.time() * 1000):
                    problems.append(f"срок инбаунда истёк ({human_time(inb.expiry_time)})")

                if email:
                    client = inb.client(email)
                    if client is None:
                        problems.append(
                            f"клиента '{email}' нет в инбаунде (есть: "
                            + (", ".join(c.email for c in inb.clients) or "никого")
                            + ")"
                        )
                    else:
                        l1.facts["client"] = client.describe(inb.protocol)
                        if not client.enable:
                            problems.append(f"клиент '{email}' отключён")
                        if client.expired:
                            problems.append(f"срок клиента истёк ({human_time(client.expiry_time)})")
                        stat = inb.stat_for(email)
                        if stat:
                            used = int(stat.get("up", 0) or 0) + int(stat.get("down", 0) or 0)
                            l1.facts["client_traffic"] = human_bytes(used)
                            if client.total_gb and used >= client.total_gb:
                                problems.append(
                                    f"клиент выбрал лимит: {human_bytes(used)} из {human_bytes(client.total_gb)}"
                                )
                            if used == 0:
                                l1.hints.append(
                                    "у клиента нулевой трафик — до сервера он ещё ни разу не доходил"
                                )
                        ips = client_ips(cli, email)
                        l1.facts["client_ips"] = ips

                l1.ok = not problems
                l1.verdict = "; ".join(problems) if problems else "инбаунд и клиент активны, лимиты не выбраны"
            try:
                l1.facts["onlines"] = onlines(cli)
            except XUIError:
                pass
        except XUIError as e:
            l1.ok = False
            l1.verdict = f"панель не отдала данные: {e.message}"
    else:
        l1.verdict = "пропущено: нет доступа к панели"
    layers.append(l1)

    ctx["inbound"] = inb
    ctx["client"] = client

    # ---------- SSH ----------
    ssh_ok = False
    if use_ssh and server.ssh.usable:
        access = check_access(server)
        ssh_ok = access.ok
        ctx["ssh_access"] = access.to_dict()

    # ---------- L2: Xray на сервере ----------
    l2 = Layer("L2", "Xray на сервере: состояние и применённый конфиг")
    l2_problems: list[str] = []

    # панель знает состояние Xray и отдаёт реально применённый конфиг — это работает
    # и там, где SSH закрыт, поэтому спрашиваем её всегда
    if cli is not None and l0.ok:
        try:
            state = server_api.xray_state(cli)
            l2.facts["xray_state"] = state.get("state")
            l2.facts["xray_version"] = state.get("version")
            if state.get("error"):
                l2_problems.append(f"Xray сообщает об ошибке: {str(state['error'])[:200]}")
            if state.get("state") is not None and str(state["state"]).lower() not in ("running", "true"):
                l2_problems.append(f"Xray в состоянии '{state['state']}'")
        except XUIError as e:
            l2.hints.append(f"статус Xray через панель недоступен: {e.message}")
        if node is not None:
            # инбаунд живёт на узле: состояние его Xray панель знает из heartbeat,
            # а в конфиге самой панели такого инбаунда быть и не должно
            l2.facts["node"] = node.summary()
            l2.facts["node_xray"] = node.xray_state
            l2_problems.extend(node.problems())
        else:
            try:
                conf = server_api.config_json(cli)
                applied = [i.get("port") for i in (conf.get("inbounds") or []) if isinstance(i, dict)]
                l2.facts["applied_ports"] = applied
                if inb is not None and inb.port not in applied:
                    l2_problems.append(
                        f"порт {inb.port} есть в панели, но отсутствует в применённом конфиге Xray "
                        f"{applied} — конфиг не перезагружен либо инбаунд не поднялся"
                    )
                # самая коварная поломка: панель и Xray работают по разным конфигам,
                # и тогда выданная панелью ссылка мертва при полностью «зелёном» сервере
                if inb is not None:
                    report_drift = drift.compare(cli, [inb])
                    for finding in report_drift.get("findings", []):
                        if email and finding.get("email") not in (None, email):
                            continue
                        l2_problems.append(f"{finding['kind']}: {finding['detail']}")
                        if finding.get("applied"):
                            l2.facts["рабочий_идентификатор"] = finding["applied"]
            except XUIError as e:
                l2.hints.append(f"применённый конфиг через панель недоступен: {e.message}")

    if ssh_ok:
        service = host.service_state(server)
        process = host.xray_process(server)
        config = host.xray_config(server)
        l2.facts.update({
            "x-ui_active": service.get("x-ui_active"),
            "journal_errors": service.get("journal_errors", [])[-6:],
            "xray_running": process.get("running"),
            "xray_binary_version": (process.get("version") or "").splitlines()[:1],
            "xray_uptime_sec": process.get("uptime_sec"),
            "config_valid": config.get("ok"),
            "config_ports": config.get("inbound_ports"),
            "routing_rules": config.get("routing_rule_count"),
        })
        if service.get("x-ui_active") != "active":
            l2_problems.append(f"служба x-ui не активна ({service.get('x-ui_active')})")
        if not process.get("running"):
            l2_problems.append("процесс xray на сервере не запущен")
        if config.get("ok") is False:
            l2_problems.append(config.get("error", "конфиг Xray нечитаем"))
            if config.get("hint"):
                l2.hints.append(config["hint"])
        if process.get("note"):
            l2.hints.append(process["note"])
        if service.get("journal_errors"):
            l2.hints.append("в журнале x-ui есть ошибки — см. facts.journal_errors")
        if config.get("ok"):
            logs = host.xray_logs(server, log_path=(config.get("log_paths") or {}).get("error", ""))
            if logs.get("errors"):
                l2.facts["xray_log_errors"] = logs["errors"][-6:]
    else:
        l2.hints.append(
            "SSH недоступен: фаервол и список слушающих портов не проверить — "
            "остальное взято через API панели"
        )
        # логи Xray панель отдаёт сама, так что без SSH мы остаёмся не слепыми
        if cli is not None and l0.ok and node is None:
            строки = server_api.xray_logs(cli, 200)
            ошибки = server_api.error_lines(строки)
            if строки:
                l2.facts["xray_log_lines"] = len(строки)
            if ошибки:
                l2.facts["xray_log_errors"] = ошибки[-6:]
                l2.hints.append("в логе Xray есть ошибки — см. facts.xray_log_errors")

    if l2.facts:
        l2.ok = not l2_problems
        l2.verdict = (
            "; ".join(l2_problems)
            if l2_problems
            else "Xray работает, порт инбаунда присутствует в применённом конфиге"
        )
    else:
        l2.verdict = "пропущено: ни SSH, ни API панели недоступны"
    layers.append(l2)

    # ---------- L3: достижимость порта ----------
    l3 = Layer("L3", "порт инбаунда доступен снаружи")
    if inb is not None:
        outside = net.tcp_connect(target_host, inb.port)
        l3.facts["host"] = target_host
        l3.facts["outside"] = outside
        inside: dict[str, Any] = {}
        if ssh_ok and node is None:
            inside = host.listening(server, inb.port)
            l3.facts["inside_listening"] = inside.get("port_listening")
            l3.facts["inside_rows"] = inside.get("port_rows")

        if outside.get("ok"):
            l3.ok = True
            l3.verdict = f"порт {inb.port} принимает соединения ({outside.get('rtt_ms')} мс)"
        else:
            l3.ok = False
            if inside.get("port_listening"):
                l3.verdict = (
                    f"изнутри сервер слушает {inb.port}, снаружи не достучаться "
                    f"({outside.get('error')}) — трафик режется между нами и сервером"
                )
                l3.hints.append("проверь ufw/iptables на хосте и security group у провайдера")
                if inside.get("bound_to_localhost"):
                    l3.hints.append(
                        "порт привязан только к 127.0.0.1 — в панели поле listen должно быть пустым"
                    )
            elif ssh_ok:
                l3.verdict = f"порт {inb.port} не слушается ни снаружи, ни на самом сервере"
                l3.hints.append("это следствие L2: Xray не применил конфиг или не запущен")
            else:
                l3.verdict = f"порт {inb.port} недоступен снаружи: {outside.get('error')}"
            if outside.get("hint"):
                l3.hints.append(outside["hint"])
    else:
        l3.verdict = "пропущено: инбаунд не выбран"
    layers.append(l3)

    # ---------- L4: TLS / Reality ----------
    l4 = Layer("L4", "TLS/Reality-хендшейк и его параметры")
    if inb is not None and l3.ok:
        if inb.security == "none":
            l4.ok = None
            l4.verdict = "у инбаунда нет TLS — слой неприменим"
        else:
            handshake = net.tls_handshake(target_host, inb.port, sni=inb.sni)
            l4.facts["handshake"] = handshake
            problems = []
            if not handshake.get("ok"):
                problems.append(f"TLS-хендшейк не прошёл: {handshake.get('error')}")
                if handshake.get("hint"):
                    l4.hints.append(handshake["hint"])

            if inb.security == "reality":
                l4.facts["sni"] = inb.sni
                l4.facts["dest"] = inb.reality_dest
                l4.facts["short_ids"] = inb.short_ids
                if not inb.public_key:
                    problems.append("в инбаунде нет публичного ключа Reality — ссылку собрать нечем")
                if not inb.sni:
                    problems.append("не задан serverName/SNI для Reality")
                if ssh_ok and inb.reality_dest:
                    dest = host.check_dest(server, inb.reality_dest)
                    l4.facts["dest_check"] = {k: v for k, v in dest.items() if k != "raw"}
                    if not dest.get("ok"):
                        problems.append(f"сервер не достукивается до dest {inb.reality_dest}")
                        if dest.get("hint"):
                            l4.hints.append(dest["hint"])
                    if dest.get("hint_tls13"):
                        l4.hints.append(dest["hint_tls13"])
                # пару ключей считаем локально — для этого сервер не нужен
                if inb.private_key and inb.public_key:
                    выведен = drift.derive_public_key(inb.private_key)
                    if выведен and выведен != inb.public_key:
                        problems.append(
                            "пара ключей Reality не сходится: из приватного выводится "
                            f"{выведен[:16]}…, а клиентам отдаётся {inb.public_key[:16]}… — "
                            "сервер не узнает ни одного клиента"
                        )
                    elif выведен:
                        l4.facts["reality_keys"] = "пара сходится"
                if ssh_ok and inb.private_key and inb.public_key:
                    keys = host.x25519_matches(server, inb.private_key, inb.public_key)
                    l4.facts["key_match"] = {k: v for k, v in keys.items() if k != "derived_public_key"}
                    if keys.get("ok") is False:
                        problems.append("публичный и приватный ключи Reality не соответствуют друг другу")
                        if keys.get("hint"):
                            l4.hints.append(keys["hint"])
            elif inb.security in ("tls", "xtls"):
                certs = inb.tls.get("certificates") or []
                l4.facts["cert_count"] = len(certs)
                if not certs:
                    problems.append("у инбаунда включён TLS, но не задан сертификат")
                if handshake.get("cert_not_after"):
                    l4.facts["cert_not_after"] = handshake["cert_not_after"]

            l4.ok = not problems
            l4.verdict = "; ".join(problems) if problems else "хендшейк проходит, параметры на месте"
    else:
        l4.verdict = "пропущено: порт недоступен либо инбаунд не выбран"
    layers.append(l4)

    # ---------- L5: семантика конфига ----------
    l5 = Layer("L5", "внутренняя согласованность конфига")
    if inb is not None:
        problems = check_semantics(inb, client)
        l5.ok = not problems
        l5.verdict = "; ".join(problems) if problems else "протокол, транспорт и flow согласованы"
        l5.facts["scheme"] = f"{inb.protocol}/{inb.network}/{inb.security}"
        if client is not None:
            l5.facts["flow"] = client.flow or "(пусто)"
    else:
        l5.verdict = "пропущено: инбаунд не выбран"
    layers.append(l5)

    # ---------- L6: выход в интернет с сервера ----------
    l6 = Layer("L6", "сервер сам ходит в интернет")
    if ssh_ok:
        eg = host.egress(server)
        l6.facts = {k: v for k, v in eg.items() if k != "dns_raw"}
        l6.ok = bool(eg.get("ok"))
        l6.verdict = (
            f"DNS и HTTPS с сервера работают, внешний IP {eg.get('external_ip')}"
            if l6.ok
            else "сервер не выходит в интернет — туннель до него бесполезен"
        )
        if eg.get("hint"):
            l6.hints.append(eg["hint"])
        clock = (host.facts(server) or {}).get("clock_warning")
        if clock:
            l6.hints.append(clock)
    else:
        l6.verdict = "пропущено: нет SSH-доступа"
    layers.append(l6)

    # ---------- L7: сквозная проверка ----------
    l7 = Layer("L7", "сквозной тест через локальный Xray")
    if run_e2e and inb is not None and client is not None:
        try:
            result = e2e.test_config(server, inb, client, host=target_host)
            l7.facts["result"] = {
                k: v for k, v in result.items() if k not in ("connectivity", "exit_ip_probe")
            }
            l7.ok = bool(result.get("passed"))
            l7.verdict = e2e.summarize(result).splitlines()[0]
            if not l7.ok and all(x.ok is not False for x in layers[:-1]):
                l7.hints.append(
                    "все серверные слои в порядке, а туннель не работает — "
                    "похоже на блокировку на стороне твоего провайдера/DPI; "
                    "проверь этот же конфиг с другой сети"
                )
        except e2e.XrayMissing as e:
            l7.verdict = str(e)
        except Exception as e:
            l7.verdict = f"тест не отработал: {type(e).__name__}: {e}"
    elif not run_e2e:
        l7.verdict = "пропущено по флагу --no-e2e"
    else:
        l7.verdict = "пропущено: нужен инбаунд и конкретный клиент (--inbound и --email)"
    layers.append(l7)

    if cli is not None:
        cli.close()

    ctx["target_host"] = target_host
    report = build_report(server, layers, ctx)
    write_json(run_dir("diag") / f"{ts()}-{server.name}.json", report)
    return report


def check_semantics(inb: Inbound, client: ClientCfg | None) -> list[str]:
    """Комбинации, которые Xray принимает на запись, но не может обслуживать."""
    problems: list[str] = []
    flow = client.flow if client else (inb.clients[0].flow if inb.clients else "")

    if flow and flow.startswith("xtls-rprx"):
        if inb.protocol != "vless":
            problems.append(f"flow={flow} допустим только для vless, а протокол {inb.protocol}")
        if inb.network != "tcp":
            problems.append(f"flow={flow} работает только с транспортом tcp, а здесь {inb.network}")
        if inb.security not in ("reality", "tls"):
            problems.append(f"flow={flow} требует reality или tls, а security={inb.security}")

    if inb.protocol == "vless" and inb.security == "none" and inb.network == "tcp":
        problems.append("vless без TLS по голому tcp — трафик виден в открытую и режется DPI")

    if inb.security == "reality":
        if not inb.reality_dest:
            problems.append("в Reality не задан dest")
        if not (inb.reality.get("serverNames") or []):
            problems.append("в Reality пустой список serverNames")
        if inb.network not in ("tcp", "grpc", "xhttp", "h2", "http"):
            problems.append(f"Reality не сочетается с транспортом {inb.network}")

    if inb.network in ("ws", "httpupgrade"):
        path = str(inb.transport_settings.get("path", "") or "")
        if not path.startswith("/"):
            problems.append(f"путь транспорта '{path}' должен начинаться со слеша")

    if inb.listen and inb.listen not in ("0.0.0.0", "::"):
        problems.append(f"инбаунд слушает только {inb.listen} — снаружи он недоступен")

    if client is not None and inb.protocol in ("vless", "vmess") and not client.uuid:
        problems.append("у клиента нет uuid")
    if client is not None and inb.protocol in ("trojan", "shadowsocks") and not client.password:
        problems.append("у клиента нет пароля")

    return problems


def build_report(server: Server, layers: list[Layer], ctx: dict[str, Any]) -> dict[str, Any]:
    failed = [l for l in layers if l.ok is False]
    first = failed[0] if failed else None
    hypotheses: list[str] = []
    if first is not None:
        hypotheses.append(f"[{first.code}] {first.verdict}")
        hypotheses.extend(first.hints)
        for layer in failed[1:]:
            hypotheses.append(f"следствие/сопутствующее [{layer.code}]: {layer.verdict}")
    else:
        unchecked = [l.code for l in layers if l.ok is None]
        hypotheses.append(
            "явных отказов не найдено"
            + (f"; не проверены слои: {', '.join(unchecked)}" if unchecked else "")
        )

    return {
        "server": server.name,
        "checked_at": ts(),
        "client_host": ctx.get("target_host") or server.client_host,
        "first_failing_layer": first.code if first else None,
        "hypotheses": hypotheses,
        "layers": [l.to_dict() for l in layers],
        "ssh": ctx.get("ssh_access"),
    }


def format_report(report: dict[str, Any]) -> str:
    lines = [f"Диагностика {report['server']} ({report['client_host']}) — {report['checked_at']}"]
    for layer in report["layers"]:
        mark = {True: "OK  ", False: "FAIL", None: "--  "}[layer["ok"]]
        lines.append(f"  {mark} {layer['code']} {layer['title']}: {layer['verdict']}")
        for hint in layer["hints"]:
            lines.append(f"        → {hint}")
    lines.append("")
    if report["first_failing_layer"]:
        lines.append(f"Первый провалившийся слой: {report['first_failing_layer']}")
    lines.append("Гипотезы:")
    for h in report["hypotheses"]:
        lines.append(f"  - {h}")
    return "\n".join(lines)
