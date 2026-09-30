"""Тесты корректной парной статистики Proof-of-Savings."""
from __future__ import annotations

import unittest

from sia.statistics import (
    holm_bonferroni,
    mcnemar_exact,
    minimum_detectable_difference,
    newcombe_paired_ci,
    non_inferiority_test,
    wilson_ci,
)


class WilsonCITestCase(unittest.TestCase):
    def test_all_successes(self) -> None:
        lower, upper = wilson_ci(10, 10, confidence=0.95)
        self.assertGreaterEqual(lower, 0.69)
        self.assertLessEqual(upper, 1.0)

    def test_zero_total(self) -> None:
        self.assertEqual(wilson_ci(0, 0), (0.0, 1.0))


class NewcombePairedCITestCase(unittest.TestCase):
    def test_no_discordance(self) -> None:
        # b=0, c=0: нет дискордантных пар, diff=0
        lower, upper = newcombe_paired_ci(0, 0, 20, confidence=0.95)
        self.assertLessEqual(lower, 0.0)
        self.assertGreaterEqual(upper, 0.0)

    def test_new_worse(self) -> None:
        # b=5 (старое прошло, новое упало), c=0: diff = -5/20 = -0.25
        lower, upper = newcombe_paired_ci(5, 0, 20, confidence=0.95)
        self.assertLess(lower, 0.0)
        self.assertLessEqual(upper, 0.0)

    def test_new_better(self) -> None:
        # b=0, c=5: diff = +0.25
        lower, upper = newcombe_paired_ci(0, 5, 20, confidence=0.95)
        self.assertGreaterEqual(lower, 0.0)
        self.assertGreater(upper, 0.0)

    def test_bounds_within_range(self) -> None:
        for b, c in [(0, 0), (3, 1), (1, 3), (10, 10)]:
            lower, upper = newcombe_paired_ci(b, c, 20, confidence=0.99)
            self.assertTrue(-1.0 <= lower <= upper <= 1.0)


class McNemarTestCase(unittest.TestCase):
    def test_no_discordance(self) -> None:
        self.assertEqual(mcnemar_exact(0, 0), 1.0)

    def test_symmetric(self) -> None:
        # b=c => p-value должен быть высоким (симметрия)
        p = mcnemar_exact(5, 5)
        self.assertGreater(p, 0.5)

    def test_asymmetric(self) -> None:
        # b=10, c=0 => сильная асимметрия, p-value низкий
        p = mcnemar_exact(10, 0)
        self.assertLess(p, 0.01)


class NonInferiorityTestCase(unittest.TestCase):
    def test_identical_results_too_small_n_is_inconclusive(self) -> None:
        """Регресс (дыра 2026-09-30): одинаковые прогоны на МАЛОМ n.

        Раньше b=c=0 обходил MDD-гейт, и n=50 «не хуже» объявлялось
        non_inferior, хотя при n=50 и допущении дискордантности 10% тест
        физически не может заметить падение на delta=0.10. Теперь такой
        прогон честно inconclusive (MDD-гейт обязателен).
        """
        old = [True] * 50
        new = [True] * 50
        result = non_inferiority_test(old, new, delta=0.10)
        self.assertEqual(result.b, 0)
        self.assertEqual(result.c, 0)
        self.assertGreater(result.mdd, 0.10)
        self.assertFalse(result.non_inferior)
        self.assertEqual(result.verdict, "inconclusive")

    def test_identical_results_large_n_non_inferior(self) -> None:
        """Регресс в другую сторону: при достаточной n одинаковые прогоны
        ДОЛЖНЫ проходить — снятие обхода не ломает честный случай."""
        old = [True] * 2000
        new = [True] * 2000
        result = non_inferiority_test(old, new, delta=0.02)
        self.assertLessEqual(result.mdd, 0.02)
        self.assertTrue(result.non_inferior)
        self.assertEqual(result.verdict, "non_inferior")

    def test_slight_degradation_within_delta(self) -> None:
        # 4 из 200 упали (2%), delta=10% => неинфериорно
        # (при n=200 интервал достаточно узкий для подтверждения)
        old = [True] * 200
        new = [True] * 196 + [False] * 4
        result = non_inferiority_test(old, new, delta=0.10)
        self.assertTrue(result.non_inferior)

    def test_severe_degradation_inferior(self) -> None:
        # 15 из 50 упали (30%), delta=10% => инфериорно
        old = [True] * 50
        new = [True] * 35 + [False] * 15
        result = non_inferiority_test(old, new, delta=0.10)
        self.assertFalse(result.non_inferior)
        self.assertEqual(result.verdict, "inferior")

    def test_mdd_reported(self) -> None:
        old = [True] * 100
        new = [True] * 100
        result = non_inferiority_test(old, new, delta=0.05)
        self.assertGreater(result.mdd, 0.0)
        self.assertLess(result.mdd, 1.0)

    def test_mdd_uses_observed_discordance_when_above_assumption(self) -> None:
        # 30 из 100 пар дискордантны (30% > допущения 10%): опубликованный
        # MDD обязан характеризовать ЭТОТ прогон, а не гипотетический с 10%.
        # Раньше MDD молча считался по 0.10 и занижал слепоту аудита ровно
        # в том случае, когда дешёвая модель реально хуже.
        old = [True] * 85 + [False] * 15
        new = [True] * 55 + [False] * 45  # b=30, c=0

        result = non_inferiority_test(old, new, delta=0.10)

        # alpha=(1-0.95)/2: вердикт читает нижнюю границу двустороннего
        # CI, MDD обязан описывать тот же односторонний тест при 2.5%
        expected = minimum_detectable_difference(
            100, alpha=0.025, power=0.80, p_discordant=0.30
        )
        self.assertAlmostEqual(result.mdd, expected, places=10)

        default_assumption = minimum_detectable_difference(
            100, alpha=0.025, power=0.80, p_discordant=0.10
        )
        self.assertGreater(result.mdd, default_assumption)

    def test_mdd_never_more_optimistic_than_assumption(self) -> None:
        # Наблюдённая дискордантность ниже допущения (2% < 10%): MDD
        # остаётся на полу-допущении — число не может стать оптимистичнее
        old = [True] * 196 + [False] * 4
        new = [True] * 200  # b=0, c=4 (новый починил 4 элемента, не сломал)

        result = non_inferiority_test(old, new, delta=0.10)

        expected = minimum_detectable_difference(
            200, alpha=0.025, power=0.80, p_discordant=0.10
        )
        self.assertAlmostEqual(result.mdd, expected, places=10)

    def test_mdd_respects_higher_explicit_assumption(self) -> None:
        # Явное допущение выше наблюдённого уважается как пол
        old = [True] * 196 + [False] * 4
        new = [True] * 200  # наблюдённая дискордантность 2%

        result = non_inferiority_test(
            old, new, delta=0.10, p_discordant_assumption=0.25
        )

        expected = minimum_detectable_difference(
            200, alpha=0.025, power=0.80, p_discordant=0.25
        )
        self.assertAlmostEqual(result.mdd, expected, places=10)

    def test_interval_golden_values_post_fix(self) -> None:
        """Золотые числа исправленной MOVER-конструкции (п.7 рецензии).

        Прежняя реализация собирала НИЖНЮЮ границу из компонентов верхней
        ((p10-l10) и (u01-p01)) — интервал был смещён вверх, а все тесты
        были направленными («lower < 0») и этого не видели. Привязка к
        числам делает повторение такой правки незамеченной невозможным.
        """
        cases = {
            (2, 3, 90): (-0.04830806639460024, 0.07337017530108143),
            (0, 0, 50): (-0.07134759913335872, 0.07134759913335872),
            (10, 2, 200): (-0.08023730580352734, -0.005748667970363226),
        }

        for (b, c, n), expected in cases.items():
            lower, upper = newcombe_paired_ci(b, c, n)

            self.assertAlmostEqual(lower, expected[0], places=12, msg=f"b={b} c={c} n={n}")
            self.assertAlmostEqual(upper, expected[1], places=12, msg=f"b={b} c={c} n={n}")

    def test_verdict_gated_by_mdd_when_ci_passes(self) -> None:
        """Случай рецензента: CI проходит на малом n, но MDD >> delta.

        Интервал в одиночку малое n не отсекает (мощность 30-51% при
        n=90); вердикт обязан запираться по MDD. И это «inconclusive»,
        а не «inferior»: хуже не доказано — недостаточно данных.
        """
        old = [True] * 88 + [False] * 2   # старое упало дважды
        new = [True] * 90                 # новое не упало ни разу

        result = non_inferiority_test(old, new, delta=0.05)

        # CI проходит: -0.0218 > -0.05
        self.assertGreater(result.ci_lower, -result.delta)
        self.assertFalse(result.non_inferior)      # но MDD = 0.0934 > 0.05
        self.assertEqual(result.verdict, "inconclusive")

    def test_zero_discordance_no_longer_exempts_from_mdd_gate(self) -> None:
        """Регресс (дыра 2026-09-30): b=c=0 больше НЕ обходит MDD-гейт.

        Именно это был PoC дыры: n=400, delta=0.02, MDD=0.0627 > 0.02 —
        тест физически не способен заметить падение на 2 п.п., но прежний
        код объявлял non_inferior «за счёт» нулевой дискордантности.
        Теперь — честный inconclusive.
        """
        old = [True] * 400
        new = [True] * 400

        result = non_inferiority_test(old, new, delta=0.02)

        self.assertGreater(result.ci_lower, -result.delta)
        self.assertGreater(result.mdd, result.delta)
        self.assertFalse(result.non_inferior)
        self.assertEqual(result.verdict, "inconclusive")

    def test_coin_flip_is_not_certified_non_inferior(self) -> None:
        """ГЛАВНЫЙ регресс: две идентичные модели точностью ровно 50%.

        Монетка неотличима от полезной системы, но провалит и относительный
        тест (MDD-гейт), и абсолютный пол — система не должна выпускать
        подтверждение «экономия доказана» для пустого результата.
        """
        old = [True] * 100 + [False] * 100
        new = [True] * 100 + [False] * 100   # идентичны => b=c=0

        result = non_inferiority_test(old, new, delta=0.05)

        self.assertEqual(result.b, 0)
        self.assertEqual(result.c, 0)
        # MDD-гейт обязателен: при n=200 он выше delta, значит вердикт НЕ
        # может быть non_inferior, какой бы «нулевой» ни была дискордантность.
        self.assertGreater(result.mdd, 0.05)
        self.assertFalse(result.non_inferior)

    def test_single_discordant_pair_blocks_at_same_n(self) -> None:
        # Одна дискордантная пара снимает исключение: при MDD > delta
        # заявление «не хуже чем на delta» не подтверждено
        old = [True] * 400
        new = [True] * 399 + [False]

        result = non_inferiority_test(old, new, delta=0.02)

        self.assertFalse(result.non_inferior)
        self.assertEqual(result.verdict, "inconclusive")

    def test_true_inferior_still_inferior(self) -> None:
        old = [True] * 50
        new = [True] * 35 + [False] * 15

        result = non_inferiority_test(old, new, delta=0.10)

        self.assertFalse(result.non_inferior)
        self.assertEqual(result.verdict, "inferior")  # ci_lower ниже маркера

    def test_mismatched_lengths_raises(self) -> None:
        with self.assertRaises(ValueError):
            non_inferiority_test([True], [True, False], delta=0.1)

    def test_to_dict(self) -> None:
        old = [True] * 20
        new = [True] * 19 + [False]
        result = non_inferiority_test(old, new, delta=0.15)
        d = result.to_dict()
        self.assertIn("non_inferior", d)
        self.assertIn("minimum_detectable_difference", d)
        self.assertIn("mcnemar_p", d)


class HolmBonferroniTestCase(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertEqual(holm_bonferroni([]), [])

    def test_single_significant(self) -> None:
        decisions = holm_bonferroni([0.001, 0.5, 0.9], alpha=0.05)
        self.assertEqual(decisions, [True, False, False])

    def test_none_significant(self) -> None:
        decisions = holm_bonferroni([0.1, 0.2, 0.3], alpha=0.05)
        self.assertEqual(decisions, [False, False, False])

    def test_all_significant(self) -> None:
        decisions = holm_bonferroni([0.001, 0.002, 0.003], alpha=0.05)
        self.assertEqual(decisions, [True, True, True])

    def test_controls_fwer(self) -> None:
        # 20 кандидатов, все p=0.04: без поправки все бы прошли,
        # с Холмом только первый (0.04 <= 0.05/20=0.0025? нет) => ни один
        decisions = holm_bonferroni([0.04] * 20, alpha=0.05)
        self.assertEqual(sum(decisions), 0)


class MDDTestCase(unittest.TestCase):
    def test_larger_n_smaller_mdd(self) -> None:
        mdd_small = minimum_detectable_difference(50)
        mdd_large = minimum_detectable_difference(500)
        self.assertGreater(mdd_small, mdd_large)

    def test_zero_n(self) -> None:
        self.assertEqual(minimum_detectable_difference(0), 1.0)


if __name__ == "__main__":
    unittest.main()
