"""Apportionment must never lose or invent a unit."""

from __future__ import annotations

import pytest

from perfgen.emit.apportion import apportion_float, largest_remainder


@pytest.mark.parametrize(
    ("total", "weights", "expected"),
    [
        (25, [60, 40], [15, 10]),
        (80, [60, 40], [48, 32]),
        # The case naive rounding gets wrong: 3 x round(3.33) = 9, losing a thread.
        (10, [33, 33, 34], [3, 3, 4]),
        (25, [33, 33, 34], [8, 8, 9]),
        (1, [50, 50], [1, 0]),
        (0, [60, 40], [0, 0]),
        (7, [100], [7]),
        (10, [25, 25, 25, 25], [3, 3, 2, 2]),
    ],
)
def test_largest_remainder_sums_exactly(total, weights, expected):
    result = largest_remainder(total, weights)
    assert result == expected
    assert sum(result) == total


@pytest.mark.parametrize(
    ("total", "weights"),
    [
        (100, [33, 33, 34]),
        (7, [1, 1, 1, 1, 1, 1]),
        (999, [17, 3, 80]),
        (13, [50, 50]),
        (5, [99, 1]),
    ],
)
def test_sum_is_preserved_for_awkward_splits(total, weights):
    assert sum(largest_remainder(total, weights)) == total


def test_zero_weights_split_evenly_rather_than_favouring_the_first():
    assert largest_remainder(10, [0, 0, 0]) == [4, 3, 3]


def test_empty_weights():
    assert largest_remainder(10, []) == []


def test_negative_total_is_rejected():
    with pytest.raises(ValueError, match="must not be negative"):
        largest_remainder(-1, [50, 50])


def test_apportion_float_splits_throughput():
    # 1200 tph is 20 samples/minute; a 60/40 split is 12 and 8.
    assert apportion_float(20.0, [60, 40]) == pytest.approx([12.0, 8.0])


def test_apportion_float_preserves_total():
    parts = apportion_float(20.0, [33, 33, 34])
    assert sum(parts) == pytest.approx(20.0)
