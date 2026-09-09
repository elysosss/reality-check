"""Сборка share-ссылок (vless://, vmess://, trojan://, ss://) и клиентских outbound'ов Xray.

Один и тот же инбаунд описывается здесь дважды и намеренно:
  * build_link()      — то, что отдаётся человеку и вставляется в клиент;
  * outbound_from()   — то, чем мы сами проверяем связь через локальный xray.
Расхождение между ними ловит ошибки в формате ссылки.
"""
from __future__ import annotations

import base64
import json
from urllib.parse import quote, urlencode

from .models import Inbound, ClientCfg


def _b64(data: str) -> str:
    return base64.b64encode(data.encode("utf-8")).decode("ascii").rstrip("=")


def _transport_params(inb: Inbound) -> dict[str, str]:
    """Параметры транспорта в формате URI-схемы v2rayN/nekoray."""
    net = inb.network
    ts = inb.transport_settings
    params: dict[str, str] = {}

    if net == "tcp":
        header = (ts.get("header") or {}).get("type", "none")
        if header and header != "none":
            params["headerType"] = str(header)
            request = (ts.get("header") or {}).get("request") or {}
            hosts = ((request.get("headers") or {}).get("Host")) or []
            if hosts:
                params["host"] = ",".join(str(h) for h in hosts)
            paths = request.get("path") or []
            if paths:
                params["path"] = str(paths[0])
    elif net in ("ws", "httpupgrade"):
        if ts.get("path"):
            params["path"] = str(ts["path"])
        host = ts.get("host") or (ts.get("headers") or {}).get("Host")
        if host:
            params["host"] = str(host)
    elif net in ("xhttp", "splithttp"):
        if ts.get("path"):
            params["path"] = str(ts["path"])
        if ts.get("host"):
            params["host"] = str(ts["host"])
        if ts.get("mode"):
            params["mode"] = str(ts["mode"])
    elif net == "grpc":
        if ts.get("serviceName"):
            params["serviceName"] = str(ts["serviceName"])
        if ts.get("multiMode"):
            params["mode"] = "multi"
    elif net in ("http", "h2"):
        if ts.get("path"):
            params["path"] = str(ts["path"])
        hosts = ts.get("host") or []
        if hosts:
            params["host"] = ",".join(str(h) for h in hosts)
    elif net == "kcp":
        header = (ts.get("header") or {}).get("type", "none")
        if header:
            params["headerType"] = str(header)
        if ts.get("seed"):
            params["seed"] = str(ts["seed"])

    return params


def _security_params(inb: Inbound) -> dict[str, str]:
    params: dict[str, str] = {}
    sec = inb.security
    if sec == "reality":
        params["security"] = "reality"
        if inb.sni:
            params["sni"] = inb.sni
        if inb.public_key:
            params["pbk"] = inb.public_key
        if inb.short_ids:
            params["sid"] = inb.short_ids[0]
        params["fp"] = inb.fingerprint or "chrome"
        spx = inb.reality_client.get("spiderX")
        if spx:
            params["spx"] = str(spx)
    elif sec in ("tls", "xtls"):
        params["security"] = sec
        if inb.sni:
            params["sni"] = inb.sni
        if inb.fingerprint:
            params["fp"] = inb.fingerprint
        alpn = inb.tls.get("alpn") or []
        if alpn:
            params["alpn"] = ",".join(str(a) for a in alpn)
        if (inb.tls.get("settings") or {}).get("allowInsecure"):
            params["allowInsecure"] = "1"
    else:
        params["security"] = "none"
    return params


def build_link(inb: Inbound, client: ClientCfg, host: str, *, remark: str = "") -> str:
    """Собирает share-ссылку для клиента. host — адрес, которым коннектятся, не адрес панели."""
    proto = inb.protocol
    label = remark or (f"{inb.remark}-{client.email}" if client.email else inb.remark)
    port = inb.port

    if proto == "vmess":
        # vmess исторически кодируется base64 от json, а не query-строкой
        ts = inb.transport_settings
        conf = {
            "v": "2",
            "ps": label,
            "add": host,
            "port": str(port),
            "id": client.uuid,
            "aid": str(client.raw.get("alterId", 0) or 0),
            "scy": str(client.raw.get("security", "auto") or "auto"),
            "net": inb.network,
            "type": str((ts.get("header") or {}).get("type", "none")),
            "host": _transport_params(inb).get("host", ""),
            "path": _transport_params(inb).get("path", ""),
            "tls": inb.security if inb.security != "none" else "",
            "sni": inb.sni,
            "alpn": ",".join(str(a) for a in (inb.tls.get("alpn") or [])),
            "fp": inb.fingerprint,
        }
        return "vmess://" + base64.b64encode(
            json.dumps(conf, ensure_ascii=False).encode("utf-8")
        ).decode("ascii")

    if proto == "shadowsocks":
        method = str(inb.settings.get("method", "") or "")
        password = client.password or str(inb.settings.get("password", "") or "")
        if method.startswith("2022"):
            # в 2022-методах пароль клиента склеивается с серверным ключом
            password = f"{inb.settings.get('password', '')}:{client.password}"
        userinfo = _b64(f"{method}:{password}")
        return f"ss://{userinfo}@{host}:{port}#{quote(label)}"

    params = _security_params(inb)
    params.update(_transport_params(inb))
    params["type"] = inb.network

    if proto == "vless":
        params["encryption"] = "none"
        if client.flow:
            params["flow"] = client.flow
        secret = client.uuid
    elif proto == "trojan":
        secret = client.password
    else:
        raise ValueError(f"протокол {proto} пока не поддержан для сборки ссылки")

    query = urlencode({k: v for k, v in params.items() if v not in ("", None)}, safe="/:,")
    return f"{proto}://{quote(secret, safe='')}@{host}:{port}?{query}#{quote(label)}"


def outbound_from(inb: Inbound, client: ClientCfg, host: str, *, tag: str = "proxy") -> dict:
    """Outbound для клиентского конфига Xray — им проверяем связь по-настоящему."""
    proto = inb.protocol
    stream: dict = {"network": inb.network}
    sec = inb.security
    if sec != "none":
        stream["security"] = sec

    if sec == "reality":
        stream["realitySettings"] = {
            "serverName": inb.sni,
            "fingerprint": inb.fingerprint or "chrome",
            "publicKey": inb.public_key,
            "shortId": inb.short_ids[0] if inb.short_ids else "",
            "spiderX": str(inb.reality_client.get("spiderX", "") or ""),
        }
        if inb.mldsa65_verify:
            # пост-квантовый Reality: имя поля симметрично серверному конфигу
            stream["realitySettings"]["mldsa65Verify"] = inb.mldsa65_verify
    elif sec in ("tls", "xtls"):
        tls_conf: dict = {"serverName": inb.sni or host}
        if inb.fingerprint:
            tls_conf["fingerprint"] = inb.fingerprint
        alpn = inb.tls.get("alpn") or []
        if alpn:
            tls_conf["alpn"] = [str(a) for a in alpn]
        if (inb.tls.get("settings") or {}).get("allowInsecure"):
            tls_conf["allowInsecure"] = True
        stream["tlsSettings"] = tls_conf

    ts = inb.transport_settings
    net = inb.network
    if net == "ws":
        stream["wsSettings"] = {"path": str(ts.get("path", "/") or "/")}
        host_hdr = ts.get("host") or (ts.get("headers") or {}).get("Host")
        if host_hdr:
            stream["wsSettings"]["headers"] = {"Host": str(host_hdr)}
    elif net == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": str(ts.get("path", "/") or "/")}
        if ts.get("host"):
            stream["httpupgradeSettings"]["host"] = str(ts["host"])
    elif net in ("xhttp", "splithttp"):
        key = "xhttpSettings" if net == "xhttp" else "splithttpSettings"
        conf = {"path": str(ts.get("path", "/") or "/")}
        if ts.get("host"):
            conf["host"] = str(ts["host"])
        if ts.get("mode"):
            conf["mode"] = str(ts["mode"])
        stream[key] = conf
    elif net == "grpc":
        stream["grpcSettings"] = {
            "serviceName": str(ts.get("serviceName", "") or ""),
            "multiMode": bool(ts.get("multiMode", False)),
        }
    elif net in ("http", "h2"):
        stream["httpSettings"] = {
            "path": str(ts.get("path", "/") or "/"),
            "host": [str(h) for h in (ts.get("host") or [])],
        }
    elif net == "kcp":
        stream["kcpSettings"] = {
            "header": ts.get("header") or {"type": "none"},
            "seed": str(ts.get("seed", "") or ""),
        }
    elif net == "tcp":
        header = ts.get("header") or {}
        if header.get("type") and header["type"] != "none":
            stream["tcpSettings"] = {"header": header}

    if proto == "vless":
        user = {"id": client.uuid, "encryption": "none"}
        if client.flow:
            user["flow"] = client.flow
        settings = {"vnext": [{"address": host, "port": inb.port, "users": [user]}]}
    elif proto == "vmess":
        user = {
            "id": client.uuid,
            "alterId": int(client.raw.get("alterId", 0) or 0),
            "security": str(client.raw.get("security", "auto") or "auto"),
        }
        settings = {"vnext": [{"address": host, "port": inb.port, "users": [user]}]}
    elif proto == "trojan":
        server = {"address": host, "port": inb.port, "password": client.password}
        if client.flow:
            server["flow"] = client.flow
        settings = {"servers": [server]}
    elif proto == "shadowsocks":
        settings = {
            "servers": [
                {
                    "address": host,
                    "port": inb.port,
                    "method": str(inb.settings.get("method", "") or ""),
                    "password": client.password or str(inb.settings.get("password", "") or ""),
                }
            ]
        }
    else:
        raise ValueError(f"протокол {proto} не поддержан для клиентского конфига")

    return {"tag": tag, "protocol": proto, "settings": settings, "streamSettings": stream}


def client_config(outbound: dict, socks_port: int, *, log_level: str = "warning") -> dict:
    """Минимальный клиентский конфиг Xray: SOCKS5 на локальном порту -> проверяемый сервер."""
    return {
        "log": {"loglevel": log_level},
        "inbounds": [
            {
                "tag": "socks-in",
                "port": socks_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            }
        ],
        "outbounds": [outbound, {"tag": "direct", "protocol": "freedom"}],
    }
