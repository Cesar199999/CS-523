"""
Trusted parameters generator.

MODIFY THIS FILE.
"""

import collections
from random import randint
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


class TrustedParamGenerator:
    """
    A trusted third party that generates random values for the Beaver triplet multiplication scheme.
    """

    def __init__(self):
        self.participant_ids: Set[str] = set()


    def add_participant(self, participant_id: str) -> None:
        """
        Add a participant.
        """
        self.participant_ids.add(participant_id)

    def retrieve_share(self, client_id: str, op_id: str) -> Tuple[Share, Share, Share]:
        """
        Retrieve a triplet of shares for a given client_id.
        """

        a = Share(101, 3)
        b = Share(101, 3)
        c = a*b
        return (a,b,c)

    # Feel free to add as many methods as you want.
