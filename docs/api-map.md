# Карта API панелей

Раздел «проверено на наших серверах» заполняется по результатам `reality-check probe` — там факты, а не документация. Всё остальное — ожидания, которые проба должна подтвердить.

## Авторизация

| Способ | Как | Где встречается |
|---|---|---|
| Bearer-токен | `Authorization: Bearer <token>`, токен в Settings → Security → API Token | новые версии |
| Cookie-сессия | `POST {root}/login` с `username`/`password` (+`twoFactorCode`), дальше cookie | все версии |
| CSRF | `GET {root}/csrf-token` → заголовок `X-CSRF-Token` на небезопасных методах | новые версии, только для cookie-сессий |

`{root}` = `url` + `webBasePath`, если он задан. Реальный путь: `https://host:2053/<basePath>/panel/api/inbounds/list`.

## Эндпоинты, которые опрашивает проба

Только читающие — проба ничего не меняет.

| Ключ | Метод | Путь |
|---|---|---|
| `inbounds.list` | GET | `/panel/api/inbounds/list` |
| `inbounds.list_slim` | GET | `/panel/api/inbounds/list/slim` |
| `inbounds.options` | GET | `/panel/api/inbounds/options` |
| `inbounds.allLinks` | GET | `/panel/api/inbounds/allLinks` |
| `inbounds.onlines.*` | POST/GET | `/panel/api/inbounds/onlines` |
| `server.status.*` | POST/GET | `/server/status` |
| `server.xrayVersion` | POST | `/server/getXrayVersion` |
| `server.configJson` | POST | `/server/getConfigJson` |
| `server.newUUID` | POST | `/server/getNewUUID` |
| `server.x25519` | POST | `/server/getNewX25519Cert` |

OpenAPI-спека панели ищется по путям `/panel/api/openapi.json` (ветка 3.x), `/panel/api-docs/openapi.json`, `/openapi.json`, `/panel/openapi.json`, `/public/openapi.json`. Если нашлась — в отчёте будет полный список путей именно этой версии.

## Изменяющие эндпоинты (используются только с `--apply`)

| Действие | Метод | Путь | Тело |
|---|---|---|---|
| создать инбаунд | POST | `/panel/api/inbounds/add` | поля модели, вложенные настройки — JSON-строками |
| обновить инбаунд | POST | `/panel/api/inbounds/update/{id}` | то же |
| удалить инбаунд | POST | `/panel/api/inbounds/del/{id}` | — |
| включить/выключить инбаунд | POST | `/panel/api/inbounds/setEnable/{id}` | `{"enable": false}` |
| добавить клиента | POST | `/panel/api/inbounds/addClient` | `{id: <inbound_id>, settings: "{\"clients\":[…]}"}` |
| обновить клиента | POST | `/panel/api/inbounds/updateClient/{clientId}` | то же; `clientId` — uuid либо пароль |
| удалить клиента | POST | `/panel/api/inbounds/{inboundId}/delClient/{clientId}` | — |

**Внимание:** три последних пути — раскладка старых веток. В 3.x их нет (404), клиенты живут отдельно: `clients/add`, `clients/update/{email}`, `clients/del/{email}` — см. раздел про ветку 3.x ниже.

Старые панели биндят form-data, новые — JSON. Клиент отправляет form и при отказе повторяет тем же телом как JSON (`XUIClient.post_compat`).

## Формат данных

- Конверт ответа: `{"success": bool, "msg": str, "obj": …}`. При ошибке HTTP-код часто остаётся 200 — смотреть на `success`.
- `settings`, `streamSettings`, `sniffing`, `allocate` — **строки с JSON внутри**.
- `totalGB` у клиента хранит **байты**, несмотря на имя. `expiryTime` — миллисекунды epoch, `0` = бессрочно.
- Счётчики трафика клиентов приходят отдельной веткой `clientStats`, а не внутри `settings.clients`.

## Проверено на наших серверах

| Сервер | Панель | Xray | Авторизация | Особенности |
|---|---|---|---|---|
| de-1 | 3.7.0 | 26.7.28 | Bearer | мультинода: узел finland, инбаунды с `nodeId` подняты на нём |
| de-2 | 3.7.0 | 26.7.28 | cookie + CSRF | токена нет, вход логином; CSRF обязателен до логина |

Обе панели отдают `openapi.json` (183 пути) — на него и стоит опираться.


## Ветка 3.x — проверено на боевых панелях (3.7.0)

Панель отдаёт собственную спецификацию: **`GET /panel/api/openapi.json`** (183
пути). Это точнее любых догадок — `probe` её забирает и кладёт в `runs/caps/`.

Серверные вызовы переехали: вместо `POST /server/*` здесь **`GET
/panel/api/server/*`**.

| Назначение | Метод и путь |
|---|---|
| статус панели и Xray | `GET /panel/api/server/status` |
| применённый конфиг Xray | `GET /panel/api/server/getConfigJson` |
| логи Xray | `POST /panel/api/server/xraylogs/{count}` |
| перезапуск Xray | `POST /panel/api/server/restartXrayService` |
| новые ключи Reality / UUID | `GET /panel/api/server/getNewX25519Cert`, `.../getNewUUID` |
| проверка Reality-target | `POST /panel/api/server/scanRealityTarget` |

**Клиенты — самостоятельная сущность, а не часть инбаунда.** Это главное отличие
ветки и источник самых неочевидных поломок (см. [cases.md](cases.md)).

| Назначение | Метод и путь |
|---|---|
| клиент по email (истина об идентификаторе) | `GET /panel/api/clients/get/{email}` |
| все клиенты | `GET /panel/api/clients/list` |
| правильные ссылки клиента | `GET /panel/api/clients/subLinks/{subId}` |
| изменить клиента (рассылается по инбаундам) | `POST /panel/api/clients/update/{email}` |
| кто сейчас онлайн | `POST /panel/api/clients/onlines` |
| IP клиента | `GET /panel/api/clients/ips/{email}` |

Инбаунды: `POST /panel/api/inbounds/update/{id}`, `POST
/panel/api/inbounds/setEnable/{id}` (тело `{"enable": false}`), `POST
/panel/api/inbounds/add`, `POST /panel/api/inbounds/del/{id}`.

Мультинода: `GET /panel/api/nodes/list` — адрес узла, состояние, `configDirty`.
У инбаунда на узле есть `nodeId`; подключаться клиенты должны к адресу узла.

Чего в этой ветке **нет**: `inbounds/onlines`, `inbounds/getClientTraffics/{email}`,
`inbounds/clientIps/{email}`, `inbounds/updateClient/{id}`. Трафик клиентов
доступен в `clientStats` внутри ответа `inbounds/list`.

Особенности, о которые легко споткнуться:

* роутер отвечает **404 и на неверный метод**, поэтому по коду ответа нельзя
  понять, существует ли путь;
* вход по логину/паролю требует CSRF-токен **до** логина, иначе 403;
* у панели есть блокировка после нескольких неудачных входов — перебор паролей
  заблокирует учётную запись на минуту;
* в Reality поле `dest` называется **`target`**; есть пост-квантовые поля
  `mldsa65Seed` / `mldsa65Verify`.
