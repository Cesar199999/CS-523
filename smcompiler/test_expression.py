"""
Unit tests for expressions.
Testing expressions is not obligatory.

MODIFY THIS FILE.
"""

from expression import Secret, Scalar


def test_expr_construction_1():
    [a, b, c] = get_secrets(1, 2, 3)
    expr = (a + b) * c * Scalar(4) + Scalar(3)
    assert repr(
        expr) == "((Secret(1) + Secret(2)) * Secret(3) * Scalar(4) + Scalar(3))"


def test_expr_construction_2():
    [a, b, c] = get_secrets(1, 2, 3)
    expr = (a + b + c) * Scalar(5) + Scalar(3) - Secret(2)
    assert repr(
        expr) == "((((Secret(1) + Secret(2)) + Secret(3)) * Scalar(5) + Scalar(3)) + Secret(2) * Scalar(-1))"


def test_expr_construction_3():
    expr = Scalar(3) - Scalar(3)
    assert repr(expr) == "(Scalar(3) + Scalar(3) * Scalar(-1))"


# ==================== HELPER FUNCTIONS ====================


def get_secrets(*numbers):
    return list(Secret(number) for number in numbers)
