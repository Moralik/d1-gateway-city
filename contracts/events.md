# События района 1 «Шлюз»

Конверт соответствует CloudEvents 1.0 и Р5. `id` — UUID сообщения, `time` — UTC с миллисекундами и `Z`, `subject` — UUID объекта, `datacontenttype` — `application/json`. В `citysig` передаётся HMAC-SHA256 в нижнем регистре hex. Подписывается строка `type + "\n" + id + "\n" + time + "\n" + sha256(canonical_json(data))`; канонический JSON — UTF‑8, отсортированные ключи, без пробелов между элементами и без экранирования Unicode.

## Публикуем

| `type` | Тема | Источник → получатель | Данные |
|---|---|---|---|
| `city.gateway.block.added.v1` | `city.events.gateway.block.added` | `/d1-gateway/api` → SOC | `block_id` (UUID), `source` и `actor_id` (`psn:…`), `reason_code` (`abuse`, `scan` или `policy`) |

Правило создаётся через `POST /api/v1/admin/block`. Поле `subject` повторяет `data.block_id`. Поля `source` и `actor_id` проходят псевдонимизацию до подписи. Каталог разрешённых полей и порядок обработки описаны в [ЛР5](../docs/privacy.md).

## Потребляем

| `type` | Тема | Источник → получатель | Данные |
|---|---|---|---|
| `city.soc.incident.opened.v1` | `city.events.soc.incident.opened` | `/d8-soc/api` → Шлюз | `incident_id` (UUID), `target_district` (`gateway`), необязательное `severity` (`low`, `medium`, `high`, `critical`; по умолчанию `medium`) |

В учебном обмене `subject` повторяет подписанный `data.incident_id`. Шлюз также проверяет фиксированные `source`, `type` и тему. Уточнение схемы с городским SOC входит в подключение к общей шине.

Шлюз записывает инцидент один раз по `incident_id`. При повторе сообщения с тем же `id`, плохой подписи, устаревшем времени или нарушении контракта потребитель пишет `event.rejected` с фиксированным кодом причины. Подробности процесса и прогоны находятся в [ЛР4](../docs/bus.md).
