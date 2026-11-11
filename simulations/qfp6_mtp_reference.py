#!/usr/bin/env python3
"""Independent, dependency-free reference oracle for QFP6 MTP-11 candidate vectors.

This intentionally does not import or mirror the Rust implementation. It specifies
sorting, the bounded ancestry window, upper-middle selection for short even histories,
and strict candidate comparison in plain Python.
"""

WINDOW = 11


def reference_median(ancestors):
    if not ancestors:
        raise ValueError("empty ancestry")
    tail = list(ancestors[-WINDOW:])
    tail.sort()
    return tail[len(tail) // 2]


def reference_accept(ancestors, candidate):
    return candidate > reference_median(ancestors)


def main():
    vectors = [
        ("odd-history", [9, 1, 5], 5, 6, True),
        ("even-short-upper-middle", [9, 1, 5, 3], 5, 5, False),
        ("strict-boundary-reject", [10, 20, 30, 40, 50], 30, 30, False),
        ("strict-boundary-accept", [10, 20, 30, 40, 50], 30, 31, True),
        ("window-drops-old-outlier", [10**30, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], 6, 7, True),
    ]
    for name, history, expected_median, candidate, expected_accept in vectors:
        actual_median = reference_median(history)
        assert actual_median == expected_median, (name, actual_median, expected_median)
        actual_accept = reference_accept(history, candidate)
        assert actual_accept is expected_accept, (name, actual_accept, expected_accept)

    # A candidate must be evaluated against its own parent's branch history.
    branch_a = [100, 200, 300]
    branch_b = [1000, 2000, 3000]
    assert reference_median(branch_a) == 200
    assert reference_median(branch_b) == 2000
    assert reference_accept(branch_a, 201) is True
    assert reference_accept(branch_b, 201) is False

    try:
        reference_median([])
    except ValueError:
        pass
    else:
        raise AssertionError("empty ancestry must fail closed")

    print("QFP6_MTP_REFERENCE_VECTORS=PASS (5 fixed vectors, 2 competing branches, empty-history rejection)")


if __name__ == "__main__":
    main()
