"""Split a total across flows by share, without losing or inventing units.

Naive rounding of a per-flow share does not sum back to the total: 25 users at 33/33/34 rounds to
8 + 8 + 9 = 25, but 10 users at the same shares rounds to 3 + 3 + 3 = 9 and one thread vanishes.
Largest-remainder apportionment floors every share and then hands the leftover units to the largest
fractional parts, so the result always sums exactly to the total.
"""

from __future__ import annotations


def largest_remainder(total: int, weights: list[int]) -> list[int]:
    """Apportion `total` across `weights`, summing exactly to `total`.

    Ties on the fractional part are broken by position, so the result is deterministic.
    """
    if not weights:
        return []
    if total < 0:
        raise ValueError(f"total must not be negative, got {total}")

    weight_sum = sum(weights)
    if weight_sum <= 0:
        # No usable shares — split as evenly as possible rather than giving everything to flow one.
        base, leftover = divmod(total, len(weights))
        return [base + (1 if i < leftover else 0) for i in range(len(weights))]

    exact = [total * w / weight_sum for w in weights]
    floors = [int(e) for e in exact]
    remainder = total - sum(floors)

    # Hand out the leftover units to the largest fractional parts first.
    order = sorted(
        range(len(weights)),
        key=lambda i: (-(exact[i] - floors[i]), i),
    )
    for i in order[:remainder]:
        floors[i] += 1
    return floors


def apportion_float(total: float, weights: list[int]) -> list[float]:
    """Split a float total (a throughput target) proportionally. No rounding is needed."""
    if not weights:
        return []
    weight_sum = sum(weights)
    if weight_sum <= 0:
        return [total / len(weights)] * len(weights)
    return [total * w / weight_sum for w in weights]
