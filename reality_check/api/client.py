"""Транспорт к API 3x-ui.

Вся хрупкость, связанная с разными версиями панели, живёт здесь:
  * webBasePath в URL;
  * две схемы авторизации (Bearer-токен новых версий и cookie-сессия старых);
  * CSRF-токен, обязательный для cookie-сессий на небезопасных методах;
  * ответ-конверт {"success": bool, "msg": str, "obj": ...}, где при ошибке
    HTTP-код часто остаётся 200.
Остальной код работает с распакованным obj и не знает про эти детали.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Literal

import requests
import urllib3

from ..config import Server
from ..util import mask

log = logging.getLogger(__name__)

AuthMode = Literal["bearer", "cookie", "none"]


class XUIError(Exception):
    """Панель ответила, но отказала (success:false) либо вернула не то, что ожидали."""

    def __init__(self, message: str, *, endpoint: str = "", status: int | None = None, body: str = ""):
        super().__init__(message)
        self.message = message
        self.endpoint = endpoint
        self.status = status
        self.body = body[:500]

    def __str__(self) -> str:
        parts = [self.message]
        if self.endpoint:
            parts.append(f"endpoint={self.endpoint}")
        if self.status is not None:
            parts.append(f"http={self.status}")
        return " | ".join(parts)


class AuthError(XUIError):
    """Не удалось авторизоваться ни токеном, ни логином."""


class XUIClient:
    """Один экземпляр на сервер. Ленивая авторизация, переавторизация при 401."""

    def __init__(self, server: Server, *, verbose: bool = False):
        self.server = server
        self.panel = server.panel
        self.verbose = verbose
        self.auth_mode: AuthMode = "none"
        self.csrf_token: str = ""
        self._authed = False

        self.s = requests.Session()
        self.s.verify = self.panel.verify_tls
        self.s.headers.update({"Accept": "application/json, text/plain, */*"})
        if not self.panel.verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ---------- URL ----------

    def url(self, path: str) -> str:
        """Абсолютный URL с учётом webBasePath. path задаётся от корня панели."""
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return self.panel.root + "/" + path.lstrip("/")

    # ---------- авторизация ----------

    def ensure_auth(self) -> AuthMode:
        if self._authed:
            return self.auth_mode
        errors: list[str] = []

        if self.panel.api_token:
            self.s.headers["Authorization"] = "Bearer " + self.panel.api_token
            if self._auth_works():
                self.auth_mode = "bearer"
                self._authed = True
                log.debug("[%s] авторизация по Bearer-токену", self.server.name)
                return self.auth_mode
            self.s.headers.pop("Authorization", None)
            errors.append("Bearer-токен (" + mask(self.panel.api_token) + ") не принят")

        if self.panel.username and self.panel.password:
            try:
                self._login_cookie()
                if self._auth_works():
                    self.auth_mode = "cookie"
                    self._authed = True
                    self._fetch_csrf()
                    log.debug("[%s] авторизация по cookie-сессии", self.server.name)
                    return self.auth_mode
                errors.append("логин прошёл, но API всё равно отвечает как неавторизованному")
            except XUIError as e:
                errors.append("логин не прошёл: " + e.message)

        if not self.panel.has_creds:
            errors.append("в servers.yaml не задано ни api_token, ни username/password")

        raise AuthError(
            "[" + self.server.name + "] не удалось авторизоваться: " + "; ".join(errors),
            endpoint=self.url("/login"),
        )

    def _auth_works(self) -> bool:
        """Дешёвая проверка: закрытый эндпоинт должен вернуть конверт, а не страницу логина."""
        r = self.s.get(self.url("/panel/api/inbounds/list"), timeout=self.panel.timeout)
        if r.status_code in (401, 403):
            return False
        if _looks_like_html(r):
            return False
        try:
            body = r.json()
        except ValueError:
            return False
        return bool(body.get("success")) if isinstance(body, dict) else False

    def _login_cookie(self) -> None:
        payload: dict[str, Any] = {
            "username": self.panel.username,
            "password": self.panel.password,
        }
        if self.panel.two_factor_code:
            payload["twoFactorCode"] = self.panel.two_factor_code

        # ветка 3.x отклоняет вход без CSRF-токена (403), поэтому берём его заранее
        self._fetch_csrf()
        headers = {"X-CSRF-Token": self.csrf_token} if self.csrf_token else {}

        last = ""
        # старые версии ждут form-data, новые — json; пробуем оба.
        for kind in ("form", "json"):
            kwargs = {"data": payload} if kind == "form" else {"json": payload}
            r = self.s.post(self.url("/login"), timeout=self.panel.timeout, headers=headers, **kwargs)
            try:
                body = r.json()
            except ValueError:
                last = "ответ не JSON (http=" + str(r.status_code) + ", " + kind + ")"
                continue
            if isinstance(body, dict) and body.get("success"):
                return
            msg = body.get("msg") if isinstance(body, dict) else body
            last = str(msg) + " (http=" + str(r.status_code) + ", " + kind + ")"
        raise XUIError(last or "панель не приняла логин", endpoint=self.url("/login"))

    def _fetch_csrf(self) -> None:
        """Cookie-сессии новых версий требуют X-CSRF-Token на POST. На старых эндпоинта нет."""
        try:
            r = self.s.get(self.url("/csrf-token"), timeout=self.panel.timeout)
        except requests.RequestException:
            return
        if r.status_code != 200:
            return
        token = r.headers.get("X-CSRF-Token", "")
        if not token:
            try:
                body = r.json()
                if isinstance(body, dict):
                    token = body.get("obj") or body.get("token") or ""
            except ValueError:
                stripped = r.text.strip()
                token = stripped if len(stripped) < 200 else ""
        if token:
            self.csrf_token = token
            self.s.headers["X-CSRF-Token"] = token
            log.debug("[%s] получен CSRF-токен", self.server.name)

    # ---------- запросы ----------

    def raw(
        self,
        method: str,
        path: str,
        *,
        data: dict | None = None,
        json_body: Any = None,
        auth: bool = True,
        timeout: int | None = None,
    ) -> requests.Response:
        """HTTP-запрос без разбора конверта. Нужен пробам возможностей панели."""
        if auth:
            self.ensure_auth()
        to = timeout or self.panel.timeout
        r = self.s.request(method.upper(), self.url(path), data=data, json=json_body, timeout=to)
        if auth and (r.status_code in (401, 403) or _looks_like_html(r)):
            # сессия могла протухнуть — один раз переавторизуемся и повторяем
            self._authed = False
            self.ensure_auth()
            r = self.s.request(method.upper(), self.url(path), data=data, json=json_body, timeout=to)
        return r

    def request(
        self,
        method: str,
        path: str,
        *,
        data: dict | None = None,
        json_body: Any = None,
        allow_fail: bool = False,
    ) -> Any:
        """Запрос с разбором конверта. Возвращает obj; при success:false кидает XUIError."""
        r = self.raw(method, path, data=data, json_body=json_body)
        endpoint = method.upper() + " " + path

        if _looks_like_html(r):
            raise XUIError(
                "вместо JSON пришёл HTML — вероятно неверный base_path либо редирект на логин",
                endpoint=endpoint,
                status=r.status_code,
                body=r.text,
            )
        try:
            body = r.json()
        except ValueError:
            raise XUIError(
                "ответ не является JSON (http=" + str(r.status_code) + ")",
                endpoint=endpoint,
                status=r.status_code,
                body=r.text,
            )

        if not isinstance(body, dict) or "success" not in body:
            # некоторые эндпоинты (например openapi.json) отдают голый объект
            return body

        if not body.get("success"):
            msg = body.get("msg") or "панель вернула success:false без пояснения"
            if allow_fail:
                return None
            raise XUIError(str(msg), endpoint=endpoint, status=r.status_code, body=json.dumps(body)[:500])

        return body.get("obj")

    def get(self, path: str, **kw) -> Any:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw) -> Any:
        return self.request("POST", path, **kw)

    def post_compat(self, path: str, payload: dict) -> Any:
        """POST, устойчивый к версии: старые панели биндят form-data, новые — JSON.

        Пробуем form, и только при отказе повторяем тем же телом как JSON.
        """
        try:
            return self.request("POST", path, data=payload)
        except XUIError as form_err:
            try:
                return self.request("POST", path, json_body=payload)
            except XUIError:
                raise form_err

    def close(self) -> None:
        self.s.close()

    def __enter__(self) -> "XUIClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _looks_like_html(r: requests.Response) -> bool:
    ctype = r.headers.get("Content-Type", "").lower()
    if "text/html" in ctype:
        return True
    head = r.text[:200].lstrip().lower()
    return head.startswith("<!doctype html") or head.startswith("<html")
