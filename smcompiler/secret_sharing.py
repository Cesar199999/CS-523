"""
Secret sharing scheme.
"""

from __future__ import annotations

from typing import List
import petrelic.bn as bn

from random import randint
import pickle


class UniquePrime():
    """ Wrapper class to fix a unique prime number at runtime.
        This is used to ensure that the same prime number is used for all shares.
    """

    unique_prime = bn.Bn.get_prime(512).int()

    # Singleton pattern.
    def __init__(self):
        pass


class Share:
    """
    A secret share in a finite field.
    """

    # Initialize a share with a value and a prime number.
    def __init__(self, value: int = None):
        """Initialize a share with a value and a prime number.

        Args:
            value (int): The value of the share. Defaults to a random integer in the finite field.
            q (int): The prime number. Defaults to a random prime of 256 bits.
        """
        self.q = UniquePrime().unique_prime
        self.value = value if value is not None else randint(0, self.q - 1)

    def __repr__(self):

        # Helps with debugging.
        return f"Share({self.value})"

    def __add__(self, other):

        if isinstance(other, int):

            # Scalar addition
            return Share((self.value + other) % self.q)

        # Share addition.
        return Share((self.value + other.value) % self.q)

    def __sub__(self, other):

        if isinstance(other, int):

            # Scalar subtraction.
            return Share((self.value - other) % self.q)

        # Share subtraction.
        return Share((self.value - other.value) % self.q)

    def __mul__(self, other):

        if isinstance(other, int):

            # Scalar multiplication.
            return Share((self.value * other) % self.q)

        # Share multiplication.
        return Share((self.value * other.value) % self.q)

    def serialize(self):
        """Generate a representation suitable for passing in a message."""

        return pickle.dumps(self)

    @staticmethod
    def deserialize(serialized) -> Share:
        """Restore object from its serialized representation."""

        return pickle.loads(serialized)


def share_secret(secret: int, num_shares: int) -> List[Share]:
    """Generate shares for a secret."""

    # Generate num_shares - 1 random shares.
    random_shares = [Share() for _ in range(num_shares - 1)]

    # Generate the last share such that the sum of all shares is equal to the secret.
    first_share = Share(secret - sum(share.value for share in random_shares))

    return random_shares + [first_share]


def reconstruct_secret(shares: List[Share]) -> int:
    """Reconstruct the secret from shares."""

    return sum(share.value for share in shares) % shares[0].q
