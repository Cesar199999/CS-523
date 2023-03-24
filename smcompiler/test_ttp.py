"""
Unit tests for the trusted parameter generator.
Testing ttp is not obligatory.

MODIFY THIS FILE.
"""

from ttp import TrustedParamGenerator, BeaverTriplet
from secret_sharing import Share


def test_nump():
    ttp = TrustedParamGenerator()

    ttp.add_participant('0')

    ttp.add_participant('1')

    ttp.add_participant('2')


def test_participants():
    ttp = TrustedParamGenerator()

    ttp.add_participant('0')
    ttp.add_participant('1')
    ttp.add_participant('2')
    ttp.add_participant('2')
    ttp.add_participant('3')

    assert ttp.participant_ids == {'0','1','2','3'}

def test_beaver():
    triplet = BeaverTriplet(3)

    assert (triplet.a * triplet.b)%101 == triplet.c
    sharea = Share(value=triplet.a)
    shareb = Share(value=triplet.b)
    sharec = Share(value=triplet.c)
    product = sharea*shareb
    assert product.value == sharec.value

    a_1, b_1, c_1 = triplet.get_share_triplets(0)
    a_2, b_2, c_2 = triplet.get_share_triplets(1)
    a_3, b_3, c_3 = triplet.get_share_triplets(2)

    sum_a = a_1 + a_2 + a_3
    sum_b = b_1 + b_2 + b_3
    sum_c = c_1 + c_2 + c_3

    assert sum_a.value == Share(value = triplet.a).value
    assert sum_b.value == Share(value = triplet.b).value
    assert sum_c.value == Share(value = triplet.c).value


def test_retrieveshare():
    ttp = TrustedParamGenerator()

    ttp.add_participant('0')
    ttp.add_participant('1')
    ttp.add_participant('2')

    assert ttp.client_number == {'0':0, '1':1, '2':2}

    s0_0 = ttp.retrieve_share('0', 'add0')
    s0_0_again = ttp.retrieve_share('0', 'add0')

    assert s0_0 == s0_0_again 

    s0_1 = ttp.retrieve_share('1', 'add0')
    s0_2 = ttp.retrieve_share('2', 'add0')

    assert (s0_0[0] + s0_1[0] + s0_2[0]) * (s0_0[1] + s0_1[1] + s0_2[1]) == (s0_0[2] + s0_1[2] + s0_2[2])

    s1_0 = ttp.retrieve_share('0', 'mul1')

    assert s0_0 != s1_0 
