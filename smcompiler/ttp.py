"""
Trusted parameters generator.

MODIFY THIS FILE.
"""

import collections
from random import randint, sample
from typing import (
    Dict,
    Set,
    Tuple,
)

from communication import Communication
from secret_sharing import(
    share_secret,
    Share,
)

# Feel free to add as many imports as you want.

class BeaverTriplet:
    """class holding beaver triplet with their shares"""

    def __init__(self, num_participant):
        self.a, self.b = sample(range(101), 2)
        self.c = (self.a * self.b)%101

        self.a_shares = share_secret(self.a, num_participant)
        self.b_shares = share_secret(self.b, num_participant)
        self.c_shares = share_secret(self.c, num_participant)
    
    def get_share_triplets(self, client_nb: int) -> Tuple[Share, Share, Share]:
        return (self.a_shares[client_nb], self.b_shares[client_nb], self.c_shares[client_nb])

class TrustedParamGenerator:
    """
    A trusted third party that generates random values for the Beaver triplet multiplication scheme.
    """

    def __init__(self):
        self.participant_ids: Set[str] = set()
        self.num_participant = len(self.participant_ids)
        self.operation_triplets = {}
        self.client_number = {}

    def add_participant(self, participant_id: str) -> None:
        """
        Add a participant.
        """
        self.participant_ids.add(participant_id)
        self.client_number[participant_id] = len(self.participant_ids)-1

    def retrieve_share(self, client_id: str, op_id: str) -> Tuple[Share, Share, Share]:
        """
        Retrieve a triplet of shares for a given client_id.
        """

        if op_id not in self.operation_triplets:   
            self.operation_triplets[op_id] = BeaverTriplet(len(self.participant_ids))

        triplet =  self.operation_triplets[op_id]
        (a,b,c) = triplet.get_share_triplets(self.client_number[client_id])
        return (a,b,c)

    # Feel free to add as many methods as you want.
