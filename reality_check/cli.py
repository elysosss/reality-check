"""Единая точка входа: python -m reality_check <команда>."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any

from . import __version__
from .api import server as server_api
from .api.client import XUIClient, XUIError
from .api.clients import (
    add_client,
    build_client,
    delete_client,
    onlines,
    resolve_client,
)
from .api.inbounds import (
    add_inbound,
    clone_payload,
    find_inbound,
    list_inbounds,
    set_inbound_enabled,
)
from .api.links import build_link
from .api.nodes import node_map, node_of, resolve_host
from .api.probe import probe_server
from .api.registry import authoritative_client
from .api.repair import apply_uuid_alignment, describe, plan_uuid_alignment
from .config import ConfigError, Server, load_servers, select
from .diag import drift, e2e, triage
from .diag.ssh import check_access
from .util import human_bytes, human_time, run_dir, table, ts, write_json


def _servers(args) -> list[Server]:
    servers = load_servers(args.config)
    names = getattr(args, "servers", None) or ([args.server] if getattr(args, "server", None) else None)
    return select(servers, names)


def _client(server: Server) -> XUIClient:
    return XUIClient(server)


# ---------------- команды ----------------

def cmd_servers(args) -> int:
    servers = load_servers(args.config)
    for srv in servers.values():
        print(srv.describe())
    return 0


def cmd_probe(args) -> int:
    rc = 0
    for srv in _servers(args):
        print(f"\n=== {srv.name} ({srv.panel.root}) ===")
        report = probe_server(srv)
        if report.get("error"):
            print(f"  НЕДОСТУПНА: {report['error']}")
            rc = 1
        elif report.get("auth_error"):
            print(f"  авторизация не прошла: {report['auth_error']}")
            rc = 1
        else:
            info = report.get("panel_info") or {}
            print(f"  авторизация: {report['auth_mode']}" + (" + CSRF" if report.get("csrf") else ""))
            if info:
                print(
                    f"  панель {info.get('panel_version')}, xray {info.get('version')} "
                    f"({info.get('state')}), внешний IP {info.get('public_ip')}"
                    + (f", ошибка: {info['error'][:120]}" if info.get("error") else "")
                )
            ok = [k for k, v in (report.get("endpoints") or {}).items() if v.get("ok")]
            bad = [k for k, v in (report.get("endpoints") or {}).items() if not v.get("ok")]
            print(f"  доступно эндпоинтов: {len(ok)} из {len(ok) + len(bad)}")
            if bad:
                print(f"  недоступны: {', '.join(bad)}")
            if report.get("openapi"):
                spec = report["openapi"]
                print(f"  openapi: {spec['source']} ({spec['path_count']} путей, версия {spec.get('version')})")
            inbounds = report.get("inbounds") or []
            print(f"  инбаундов: {len(inbounds)}")
        for note in report.get("notes", []):
            print(f"  ! {note}")
        print(f"  отчёт: runs/caps/{srv.name}.json")
    return rc


def cmd_inventory(args) -> int:
    rows: list[list[Any]] = []
    snapshot: dict[str, Any] = {}
    rc = 0
    for srv in _servers(args):
        try:
            with _client(srv) as cli:
                inbounds = list_inbounds(cli)
                online = set(onlines(cli))
                node_by_id = node_map(cli)
                snapshot[srv.name] = [i.raw for i in inbounds]
                for inb in inbounds:
                    used = inb.up + inb.down
                    node = node_of(inb, node_by_id)
                    rows.append([
                        srv.name,
                        inb.id,
                        inb.remark,
                        f"{inb.protocol}/{inb.network}/{inb.security}",
                        inb.port,
                        node.name if node else "(панель)",
                        resolve_host(srv, inb, node_by_id),
                        "да" if inb.enable else "НЕТ",
                        len(inb.clients),
                        human_bytes(used),
                    ])
        except (XUIError, OSError) as e:
            rc = 1
            rows.append([srv.name, "-", f"ОШИБКА: {e}", "", "", "", "", "", "", ""])

    print(table(rows, ["сервер", "id", "имя", "схема", "порт", "узел", "адрес", "вкл", "клиентов", "трафик"]))
    if snapshot:
        path = run_dir("inventory") / f"{ts()}.json"
        write_json(path, snapshot)
        print(f"\nсырые данные: {path}")
    return rc


def cmd_clients(args) -> int:
    srv = _servers(args)[0]
    with _client(srv) as cli:
        inb = find_inbound(cli, args.inbound)
        online = set(onlines(cli))
        rows = []
        устарело = 0
        for c in inb.clients:
            stat = inb.stat_for(c.email) or {}
            used = int(stat.get("up", 0) or 0) + int(stat.get("down", 0) or 0)
            # показываем идентификатор из таблицы клиентов: копия в инбаунде бывает мёртвой
            настоящий, warning = authoritative_client(cli, inb, c.email)
            секрет = (настоящий or c).secret(inb.protocol)
            if warning:
                устарело += 1
            rows.append([
                (c.email or "-") + (" !" if warning else ""),
                секрет[:12] + "…",
                "да" if c.enable else "НЕТ",
                "да" if c.email in online else "-",
                human_bytes(used),
                human_bytes(c.total_gb) if c.total_gb else "∞",
                human_time(c.expiry_time),
                c.flow or "-",
            ])
        print(f"{srv.name} #{inb.id} {inb.remark} ({inb.protocol}/{inb.network}/{inb.security}, порт {inb.port})")
        print(table(rows, ["email", "секрет", "вкл", "онлайн", "трафик", "лимит", "до", "flow"]))
        if устарело:
            print("")
            print(f"! у {устарело} клиентов копия в инбаунде устарела (помечены '!'):"
                  f" показан рабочий идентификатор из таблицы клиентов,"
                  f" ссылки панели по ним мертвы")
    return 0


def cmd_link(args) -> int:
    srv = _servers(args)[0]
    with _client(srv) as cli:
        inb, client = resolve_client(cli, args.inbound, args.email)
        print(build_link(inb, client, resolve_host(srv, inb, node_map(cli))))
    return 0


def cmd_add_client(args) -> int:
    srv = _servers(args)[0]
    with _client(srv) as cli:
        inb = find_inbound(cli, args.inbound)
        if inb.client(args.email):
            print(f"клиент '{args.email}' уже есть в инбаунде #{inb.id}")
            return 1
        entry = build_client(
            inb,
            args.email,
            cli=cli,
            limit_ip=args.limit_ip,
            total_gb=args.gb,
            expiry_days=args.days,
        )
        result = add_client(cli, inb, entry, apply=args.apply)
        if result["dry_run"]:
            print("DRY-RUN, ничего не отправлено. Запись, которая была бы создана:")
            print(json.dumps(entry, indent=2, ensure_ascii=False))
            print("\nПовтори с --apply, чтобы создать.")
            return 0
        inb = find_inbound(cli, inb.id)
        client = inb.client(args.email)
        if client is None:
            print("панель приняла запрос, но клиента в инбаунде нет — проверь версию панели")
            return 1
        print(f"создан клиент '{args.email}' в #{inb.id} ({srv.name})")
        print(build_link(inb, client, resolve_host(srv, inb, node_map(cli))))
    return 0


def cmd_del_client(args) -> int:
    srv = _servers(args)[0]
    with _client(srv) as cli:
        inb, client = resolve_client(cli, args.inbound, args.email)
        snap = run_dir("snapshots") / f"{ts()}-{srv.name}-inbound{inb.id}.json"
        write_json(snap, inb.raw)
        result = delete_client(cli, inb, client, apply=args.apply)
        if result["dry_run"]:
            print(f"DRY-RUN: удалил бы '{args.email}' из #{inb.id} ({result['endpoint']})")
            print("Повтори с --apply.")
            return 0
        print(f"удалён '{args.email}' из #{inb.id}. Снапшот инбаунда: {snap}")
    return 0


def cmd_clone_inbound(args) -> int:
    srv = _servers(args)[0]
    with _client(srv) as cli:
        source = find_inbound(cli, getattr(args, "from"))
        payload = clone_payload(
            source,
            port=args.port,
            remark=args.remark,
            cli=cli if args.apply else None,
            fresh_reality=not args.keep_keys,
        )
        result = add_inbound(cli, payload, apply=args.apply)
        if result["dry_run"]:
            print(f"DRY-RUN: создал бы инбаунд по образцу #{source.id} ({source.summary()})")
            print(f"  порт {args.port}, имя '{args.remark}', схема {source.protocol}/{source.network}/{source.security}")
            print("  клиенты не копируются — добавляй их командой add-client")
            print("Повтори с --apply.")
            return 0
        print(f"создан инбаунд '{args.remark}' на порту {args.port} по образцу #{source.id}")
        print("добавь клиента: python -m reality_check add-client "
              f"{srv.name} '{args.remark}' --email <имя> --apply")
    return 0


def cmd_drift(args) -> int:
    """Сверка базы панели с конфигом, который реально работает в Xray."""
    rc = 0
    for srv in _servers(args):
        print(f"=== {srv.name} ===")
        try:
            with _client(srv) as cli:
                report = drift.compare(cli, list_inbounds(cli))
        except (XUIError, OSError) as e:
            print(f"  ОШИБКА: {e}")
            rc = 1
            continue
        lines = drift.summarize(report)
        if report.get("error"):
            print(f"  {lines[0]}")
            rc = 1
        elif not lines:
            print(f"  расхождений нет (сверено инбаундов: {report['checked']}, "
                  f"на узлах пропущено: {report['skipped_nodes']})")
        else:
            rc = 1
            print(f"  найдено расхождений: {len(lines)} "
                  f"(сверено инбаундов: {report['checked']}, на узлах пропущено: {report['skipped_nodes']})")
            for line in lines:
                print(f"    - {line}")
            print("  панель и Xray работают по разным конфигам: ссылки из панели могут не работать")
        write_json(run_dir("drift") / f"{srv.name}.json", report)
    return rc


def cmd_fix_drift(args) -> int:
    """Приводит идентификаторы в базе панели к тем, по которым работает Xray."""
    srv = _servers(args)[0]
    with _client(srv) as cli:
        inbounds = list_inbounds(cli)
        try:
            plan = plan_uuid_alignment(cli, inbounds)
        except XUIError as e:
            print(f"не удалось построить план: {e}")
            return 1
        if not plan:
            print("расхождений по идентификаторам нет — чинить нечего")
            return 0

        print(f"правок к применению: {len(plan)}")
        for line in describe(plan):
            print(f"  - {line}")
        затронуты = sorted({p["email"] for p in plan})
        print(f"затронутые клиенты: {', '.join(затронуты)}")
        print("действующие ссылки этих людей продолжат работать: панель приводится")
        print("к тому, что уже работает на сервере, сам Xray не трогаем")

        if not args.apply:
            print("")
            print("DRY-RUN. Повтори с --apply, чтобы записать.")
            return 0

        snap = run_dir("snapshots") / f"{ts()}-{srv.name}-before-fix-drift.json"
        write_json(snap, [i.raw for i in inbounds])
        print(f"снапшот инбаундов до правок: {snap}")
        results = apply_uuid_alignment(cli, inbounds, plan, apply=True, limit=args.limit)
        ok = sum(1 for r in results if not r.get("error") and not r.get("skipped"))
        for r in results:
            mark = "ОШИБКА" if r.get("error") else ("пропуск" if r.get("skipped") else "готово")
            print(f"  {mark}: #{r['inbound_id']} {r['email']} {r.get('error') or r.get('skipped') or ''}")
        print(f"применено правок: {ok} из {len(results)}")
        return 0 if ok == len(results) else 1


def cmd_inbound_enable(args) -> int:
    """Включает или выключает инбаунд целиком."""
    srv = _servers(args)[0]
    включить = not args.off
    with _client(srv) as cli:
        inb = find_inbound(cli, args.inbound)
        snap = run_dir("snapshots") / f"{ts()}-{srv.name}-inbound{inb.id}.json"
        write_json(snap, inb.raw)
        res = set_inbound_enabled(cli, inb.id, включить, apply=args.apply)
        действие = "включил бы" if включить else "выключил бы"
        if res["dry_run"]:
            print(f"DRY-RUN: {действие} #{inb.id} ({inb.protocol}/{inb.network}/{inb.security}, порт {inb.port})")
            print(f"вызов: POST {res['endpoint']} {res['body']}")
            print("Повтори с --apply.")
            return 0
        print(f"инбаунд #{inb.id} теперь {'включён' if включить else 'выключен'}. Снапшот: {snap}")
        state = server_api.xray_state(cli)
        print(f"состояние Xray: {state.get('state')}" + (f" — {state['error'][:160]}" if state.get("error") else ""))
    return 0


def cmd_test(args) -> int:
    srv = _servers(args)[0]
    with _client(srv) as cli:
        inb, client = resolve_client(cli, args.inbound, args.email)
        host = resolve_host(srv, inb, node_map(cli))
    try:
        result = e2e.test_config(srv, inb, client, host=host)
    except e2e.XrayMissing as err:
        print(err)
        return 2
    print(e2e.summarize(result))
    return 0 if result.get("passed") else 1


def cmd_diag(args) -> int:
    rc = 0
    for srv in _servers(args):
        report = triage.diagnose(
            srv,
            inbound_ref=args.inbound,
            email=args.email,
            use_ssh=not args.no_ssh,
            run_e2e=not args.no_e2e,
        )
        print(triage.format_report(report))
        print()
        if report["first_failing_layer"]:
            rc = 1
    return rc


def cmd_ssh_check(args) -> int:
    rc = 0
    for srv in _servers(args):
        if not srv.ssh.usable:
            print(f"{srv.name}: SSH не настроен")
            rc = 1
            continue
        r = check_access(srv)
        if r.ok:
            print(f"{srv.name}: OK — {r.out.replace(chr(10), ' / ')}")
        else:
            print(f"{srv.name}: НЕТ ДОСТУПА — {r.error or r.stderr.strip()[:200]}")
            rc = 1
    return rc


def cmd_fetch_xray(args) -> int:
    info = e2e.fetch_xray(force=args.force)
    if info.get("downloaded"):
        print(f"скачан {info['asset']} → {info['path']} ({info['size']} байт)")
    else:
        print(f"{info['path']}: {info['note']}")
    return 0


# ---------------- разбор аргументов ----------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="reality-check", description="управление и диагностика 3x-ui / Xray")
    p.add_argument("--config", default=None, help="путь к servers.yaml")
    p.add_argument("-v", "--verbose", action="store_true", help="подробный лог")
    p.add_argument("--version", action="version", version=f"reality-check {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("servers", help="показать настроенные серверы")
    s.set_defaults(func=cmd_servers)

    s = sub.add_parser("probe", help="прощупать возможности панелей")
    s.add_argument("servers", nargs="*", help="имена серверов (по умолчанию все)")
    s.set_defaults(func=cmd_probe)

    s = sub.add_parser("inventory", help="сводка по инбаундам всех серверов")
    s.add_argument("servers", nargs="*")
    s.set_defaults(func=cmd_inventory)

    s = sub.add_parser("drift", help="сверить базу панели с применённым конфигом Xray")
    s.add_argument("servers", nargs="*")
    s.set_defaults(func=cmd_drift)

    s = sub.add_parser("fix-drift", help="привести базу панели к работающему конфигу Xray")
    s.add_argument("server")
    s.add_argument("--apply", action="store_true", help="реально записать (без флага — dry-run)")
    s.add_argument("--limit", type=int, default=0, help="применить только первые N правок")
    s.set_defaults(func=cmd_fix_drift)

    s = sub.add_parser("inbound-enable", help="включить/выключить инбаунд")
    s.add_argument("server")
    s.add_argument("inbound", help="id или remark инбаунда")
    s.add_argument("--off", action="store_true", help="выключить (по умолчанию включить)")
    s.add_argument("--apply", action="store_true", help="реально применить")
    s.set_defaults(func=cmd_inbound_enable)

    s = sub.add_parser("clients", help="клиенты инбаунда")
    s.add_argument("server")
    s.add_argument("inbound", help="id или remark инбаунда")
    s.set_defaults(func=cmd_clients)

    s = sub.add_parser("link", help="share-ссылка клиента")
    s.add_argument("server")
    s.add_argument("inbound")
    s.add_argument("email")
    s.set_defaults(func=cmd_link)

    s = sub.add_parser("add-client", help="добавить клиента в инбаунд")
    s.add_argument("server")
    s.add_argument("inbound")
    s.add_argument("--email", required=True)
    s.add_argument("--days", type=int, default=0, help="срок действия в днях (0 — бессрочно)")
    s.add_argument("--gb", type=float, default=0, help="лимит трафика в ГБ (0 — без лимита)")
    s.add_argument("--limit-ip", type=int, default=0, help="лимит одновременных IP")
    s.add_argument("--apply", action="store_true", help="действительно создать (иначе dry-run)")
    s.set_defaults(func=cmd_add_client)

    s = sub.add_parser("del-client", help="удалить клиента")
    s.add_argument("server")
    s.add_argument("inbound")
    s.add_argument("email")
    s.add_argument("--apply", action="store_true")
    s.set_defaults(func=cmd_del_client)

    s = sub.add_parser("clone-inbound", help="создать инбаунд по образцу работающего")
    s.add_argument("server")
    s.add_argument("--from", required=True, help="id или remark исходного инбаунда")
    s.add_argument("--port", type=int, required=True)
    s.add_argument("--remark", required=True)
    s.add_argument("--keep-keys", action="store_true", help="не выпускать новые ключи Reality")
    s.add_argument("--apply", action="store_true")
    s.set_defaults(func=cmd_clone_inbound)

    s = sub.add_parser("test", help="сквозная проверка конфига через локальный xray")
    s.add_argument("server")
    s.add_argument("inbound")
    s.add_argument("email")
    s.set_defaults(func=cmd_test)

    s = sub.add_parser("diag", help="послойная диагностика")
    s.add_argument("servers", nargs="*")
    s.add_argument("--inbound", default=None)
    s.add_argument("--email", default=None)
    s.add_argument("--no-ssh", action="store_true", help="не ходить на сервер по SSH")
    s.add_argument("--no-e2e", action="store_true", help="пропустить сквозной тест")
    s.set_defaults(func=cmd_diag)

    s = sub.add_parser("ssh-check", help="проверить SSH-доступ к серверам")
    s.add_argument("servers", nargs="*")
    s.set_defaults(func=cmd_ssh_check)

    s = sub.add_parser("fetch-xray", help="скачать xray-core в tools/ (нужен для test)")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_fetch_xray)

    return p


def _force_utf8() -> None:
    """Консоль Windows по умолчанию не в UTF-8 — иначе весь русский вывод превращается в кашу."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8()
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    try:
        return args.func(args)
    except ConfigError as e:
        print(f"ошибка конфигурации: {e}", file=sys.stderr)
        return 2
    except XUIError as e:
        print(f"панель отказала: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
