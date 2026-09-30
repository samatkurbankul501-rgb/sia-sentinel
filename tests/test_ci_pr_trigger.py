"""Регрессия: PR-гейт CI обязан реально срабатывать.

ДЫРА (найдена 2026-09-30 при коммите security-ветки): в `.github/workflows/ci.yml`
было

    pull_request:
      branches: [ main ]

а репозиторий живёт на ветке `master`. Следствие: pull_request-триггер не
срабатывал НИКОГДА — CI на PR не запускался, и «зелёный PR» означал
«никто ничего не проверял». Ровно тот класс дыр, ради которого существует
drift-guard: гейт, который тихо ничего не делает.

Тест читает реальный ci.yml и проверяет инвариант: если push-триггер
содержит `master`, то и pull_request обязан его содержать.
"""
from __future__ import annotations

import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


class PullRequestTriggerTestCase(unittest.TestCase):
    """pull_request-триггер должен покрывать ветку, на которой живёт проект."""

    def setUp(self) -> None:
        self.workflow = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
        # PyYAML читает ключ `on:` как True (YAML 1.1 boolean) — это известная
        # ловушка, обходим её обоими вариантами написания.
        self.on = self.workflow.get("on", self.workflow.get(True))

        self.assertIsInstance(self.on, dict, "ci.yml: секция `on:` не разобрана")

    def test_pull_request_trigger_covers_the_default_branch(self) -> None:
        push_branches = self.on.get("push", {}).get("branches", [])
        pr_branches = self.on.get("pull_request", {}).get("branches", [])

        self.assertIn(
            "master",
            push_branches,
            "push-триггер обязан покрывать master (это текущая ветка проекта)",
        )
        self.assertIn(
            "master",
            pr_branches,
            "pull_request-триггер обязан покрывать master: иначе CI на PR "
            "не запускается и гейт молча ничего не проверяет (дыра 2026-09-30)",
        )

    def test_pull_request_trigger_is_not_empty(self) -> None:
        pr = self.on.get("pull_request")
        self.assertTrue(
            pr,
            "в ci.yml нет триггера pull_request — PR не будут проверяться",
        )
        self.assertTrue(
            pr.get("branches"),
            "pull_request без фильтра branches допустим (сработает на любую "
            "ветку), но пустой список — ошибка конфигурации",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
