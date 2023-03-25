"""
Unit tests for the trusted parameter generator.
Testing ttp is not obligatory.

MODIFY THIS FILE.
"""

from ttp import TrustedParamGenerator


def test_constructor():
    ttp = TrustedParamGenerator()
    assert ttp.participant_ids == set()


def test_add_participant():
    ttp = TrustedParamGenerator()
    ttp.add_participant("1")
    assert ttp.participant_ids == {"1"}


def test_retrieve_share():
    ttp = TrustedParamGenerator()
    _ = [ttp.add_participant(str(i)) for i in range(1, 4)]
    share = ttp.retrieve_share("1", "op_id")
    assert share == ttp.retrieve_share("1", "op_id")
    assert share != ttp.retrieve_share("2", "op_id")
    assert share != ttp.retrieve_share("3", "op_id")


def test_beaver_triplets_consistency_1():
    ttp = TrustedParamGenerator()
    _ = [ttp.add_participant(str(i)) for i in range(1, 4)]
    shares = [ttp.retrieve_share(str(i), "op_id") for i in range(1, 4)]
    [a, b, c] = [sum(col) for col in zip(*shares)]
    assert (a * b).value == c.value


def test_beaver_triplets_consistency_2():
    ttp = TrustedParamGenerator()
    _ = [ttp.add_participant(str(i)) for i in range(1, 10)]
    shares = [ttp.retrieve_share(str(i), "op_id") for i in range(1, 10)]
    [a, b, c] = [sum(col) for col in zip(*shares)]
    assert (a * b).value == c.value


def test_beaver_triplets_persisting_consistency():
    ttp = TrustedParamGenerator()
    _ = [ttp.add_participant(str(i)) for i in range(1, 10)]
    shares = [ttp.retrieve_share(str(i), "op_id") for i in range(1, 10)]
    [a, b, c] = [sum(col) for col in zip(*shares)]
    assert (a * b).value == c.value

    next_shares = [ttp.retrieve_share(str(i), "op_id") for i in range(1, 10)]
    [next_a, next_b, next_c] = [sum(col) for col in zip(*next_shares)]
    assert (next_a * next_b).value == next_c.value
    assert [a.value, b.value, c.value] == [
        next_a.value, next_b.value, next_c.value]
