"""
Trusted parameters generator.

MODIFY THIS FILE.
"""

from random import randint
from typing import (
    Dict,
    Set,
    Tuple,
)

from secret_sharing import (
    UniquePrime,
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
        self.__operation_id_to_user_id_to_shares: Dict[str,
                                                       Dict[str, Tuple[Share, Share, Share]]] = {}

    def add_participant(self, participant_id: str) -> None:
        """
        Add a participant.
        """
        self.participant_ids.add(participant_id)

    def retrieve_share(self, client_id: str, op_id: str) -> Tuple[Share, Share, Share]:
        """
        Retrieve a triplet of shares for a given client_id. The triplet (a, b, c) is such that a * b = c.
        """
        if op_id not in self.__operation_id_to_user_id_to_shares:
            self.__operation_id_to_user_id_to_shares[op_id] = self.generate_triplets(
            )

        return self.__operation_id_to_user_id_to_shares[op_id][client_id]

    def generate_triplets(self) -> Dict[str, Tuple[Share, Share, Share]]:
        """
        Generate a random triplet of shares for each participant.
        """
        [share_a, share_b] = [share_secret(randint(0, UniquePrime().get_unique_prime()), len(
            self.participant_ids)) for _ in range(2)]

        # Use the following formula to generate the third share:
        # c = a * b = sum(a_i) * sum(b_j) = sum(a_i * sum(b_j)) =
        #
        # sum(a_i * sum(b_0 + b_1 + ... + b_i + ... + b_n)) =
        #
        # sum(a_i * b_i + a_i * (sum(b_0 + b_1 + ... + b_n) - b_i))
        #
        # Therefore,
        # c_i = a_i * b_i + a_i * (sum(b_0 + b_1 + ... + b_n) - b_i)

        share_c = [share_a[i] * share_b[i] + share_a[i] *
                   (sum(share_b) - share_b[i]) for i in range(len(share_a))]

        return {client_id: (share_a[i], share_b[i], share_c[i]) for i, client_id in enumerate(self.participant_ids)}
