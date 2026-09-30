# Публикация sia-verifier на PyPI — ✅ ВЫПОЛНЕНО 2026-09-06

> **1.6.0 (2026-09-30): собрана — security-release, ЗАГРУЗКА ЖДЁТ ОПЕРАТОРА.**
> Внешний аудит 2026-09-30 нашёл в верификаторе CRITICAL-дыру: публичный
> ключ эмитента брался ИЗ проверяемой аттестации (`core.py`), поэтому
> одноразовый Ed25519-ключ злоумышленника давал «валидную» подделку — то
> есть инструмент, которым контрагент проверяет аудитора, не доказывал
> аутентичность эмитента. Исправлено: (а) новый флаг `--issuer-key`
> (внеполосный якорь) — ключ в артефакте обязан совпасть; вердикт получил
> поле `trust_established`; (б) БЕЗ якоря CLI fail-closed (больше не печатает
> `VERDICT: VALID` при самообъявленном ключе); (в) чекпойнты проверяются
> якорем, а не самообъявленным ключом; (г) `--require-coverage` без файла
> чекпойнтов = FAIL (усечение хвоста цепи неотличимо от полной).
> Ломающий фикс → минор. Вторая дыра того же аудита — в статистике
> (`sia/statistics.py`): обход `or (b==0 and c==0)` позволял объявить
> non_inferior прогон, физически не способный заметить падение на delta
> (MDD > delta) — две идентичные 50%-модели получали non_inferior; обход
> снят, MDD-гейт обязателен. Обе дыры закрыты регрессионными тестами,
> проверенными мутацией (падают без фикса). Также исправлен `Homepage` в
> pyproject (указывал на несуществующий `sia-sentinel/sia-sentinel` вместо
> `Abzal-000/sia-sentinel`). Полный сьют 819 тестов OK, батарея
> фальсификации 31/31, обе записи VALID под `--require-coverage
> --issuer-key`. Загрузка — тот же twine-протокол ниже.
>
> **1.5.0 (2026-09-15): собрана заново и верифицирована — чистый venv,
> обе записи VALID под `--require-coverage`, rederive живым Rekor; исходник
> не менялся с 2026-09-13. Загрузка на PyPI ЖДЁТ ОПЕРАТОРА.** Накоплено
> с неопубликованной 1.3.1: (а) `--checkpoint` понимает JSONL-журнал
> снимков — проверяются ВСЕ строки (нужно после второго чекпойнта seq=4;
> 1.3.0 на двухснимочном журнале честно падает); (б) BOM-толерантность
> (PowerShell `>`-редирект); (в) лаг чекпойнт-покрытия видим — advisory +
> гейт `--require-coverage`; (г) **проверка №9 в rederive: RFC 6962
> inclusion-proof Rekor локальным фолдом** (два индекса шардированного
> инстанса не взаимозаменяемы — своп ловится); (д) timestamped-снапшот
> Rekor как офлайн-fallback (живой запрос всегда предпочителен, возраст
> виден как `snapshot:Nd`). Версия — минор по правилу
> «новая проверка = минор» (1.4.1 — патч поверх: снапшот-фолбэк не меняет
> набор проверок). Артефакты: `verifier/dist/sia_verifier-1.5.0*`. 1.5.0 — минор поверх 1.4.1: проверка №10 (проекция аттестации vs отчёт — канал найден питч-демо demo_forgery.py); 1.4.1 не публиковалась.
> Загрузка — тот же twine-протокол ниже (15 минут, PyPI-токен).

**Статус: ОПУБЛИКОВАНО.** `pip install sia-verifier` работает для любого
человека; подтверждено установкой из чистого venv и верификацией записи №1
(`VERDICT: VALID`), метаданные живые: pypi.org/pypi/sia-verifier/json →
version 1.3.0, wheel + sdist на месте. Раздел ниже оставлен как протокол
проведённой процедуры; правила версий (в конце) — действующие.

Протокол (2026-09-06, фактический): аккаунт + 2FA → API-токен (в менеджер
паролей) → `twine upload dist/*` из PowerShell (формат «Enter your API
token», токен целиком) → проверка в чистом venv
(`pip install sia-verifier` → `sia-verifier attestation.json --chain
registry.jsonl --checkpoint checkpoints.jsonl --require-coverage --issuer-key
<КЛЮЧ_ЭМИТЕНТА>` → VERDICT: VALID + `issuer trust: ESTABLISHED`).

## Что уже сделано (не повторять)

- `verifier/pyproject.toml`: версия 1.3.0, четыре console-скрипта.
- `sia_verifier/__init__.py`: 1.3.0, описание CLI.
- Сборка: `cd verifier && python -m build` → `dist/sia_verifier-1.3.0*`.
- Изолированная проверка: venv без проекта → `pip install <wheel>` →
  все команды отработали на `artifacts/record1`.

## Шаги оператора (один раз, ~15 минут)

1. **Аккаунт PyPI** (если нет): https://pypi.org/account/register/
   — подтвердить email, включить 2FA (обязательно для аплоада).

2. **API-токен**: pypi.org → Account settings → API tokens →
   «Add API token», scope: «Entire account» (для первого пакета) или
   проект будет создан при первом аплоаде. Токен вида
   `pypi-AgEIcHlwaS5vcmc...` — В МЕНЕДЖЕР ПАРОЛЕЙ, не в чат и не в файлы
   репозитория.

3. **Проверка перед аплоадом** (опционально, но рекомендовано):
   сначала на TestPyPI (отдельный токен, отдельный аккаунт —
   https://test.pypi.org):
   ```bash
   cd verifier
   ../venv/Scripts/python.exe -m twine upload --repository testpypi dist/*
   # затем проверка установки ОТТУДА в чистый venv
   ```

4. **Аплоад на PyPI**:
   ```bash
   cd verifier
   ../venv/Scripts/python.exe -m twine upload dist/*
   # username: __token__, password: <API-токен целиком>
   ```

5. **Немедленная проверка** (чистый venv):
   ```bash
   python -m venv %TEMP%/sia_check && %TEMP%/sia_check/Scripts/pip install sia-verifier
   %TEMP%/sia_check/Scripts/sia-verifier artifacts/record1/attestation.json
   ```

6. **После успеха**: обновить эту страницу (пометить «опубликовано»),
   убрать оговорку «до публикации» из verify-in-5-minutes.md и
   record1-how-to-reverify.md, закоммитить.

## Правила версий

- 1.3.0 — текущая (replay Б2 + rederive + holdout); 1.2.0 — была первая
  это серверная часть).
- Любое изменение `core.py`/`rederive.py`/`holdout.py` → бамп версии
  (патч — багфикс, минор — новая проверка/команда) и пересборка.

## Если название занято

`pypi.org/project/sia-verifier` — проверить перед аплоадом. Если вдруг
занято (маловероятно): варианты `sia-attestation-verifier`, `sia-sentinel-verifier`;
тогда поменять `name` в pyproject.toml, пересобрать, обновить все
упоминания в README/docs.
