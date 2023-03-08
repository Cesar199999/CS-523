"""
Secret sharing scheme.
"""

from __future__ import annotations

from typing import List

import random
import pickle


class Share:
    """
    A secret share in a finite field.
    """

    def __init__(self, q: int, N: int, value: int = None):
        self.q = q
        self.N = N
        self.value = value if value is not None else random.randint(0, q)

    def __repr__(self):

        # Helps with debugging.
        return f"Share({self.value})"

    def __add__(self, other):

        # Typecheck
        self.typecheck_share(other)

        # Add the shares
        return Share(self.q, self.N, (self.value + other.value) % self.q)

    def __sub__(self, other):

        # Typecheck
        self.typecheck_share(other)

        # Subtract the shares
        return Share(self.q, self.N, (self.value - other.value) % self.q)

    def __mul__(self, other):

        # Typecheck
        self.typecheck_share(other)

        # Multiply the shares
        return Share(self.q, self.N, (self.value * other.value) % self.q)

    def serialize(self):
        """Generate a representation suitable for passing in a message."""

        return pickle.dumps(self)

    @staticmethod
    def deserialize(serialized) -> Share:
        """Restore object from its serialized representation."""

        return pickle.loads(serialized)

    def typecheck_share(self, other: Share) -> None:
        """Check if the share is from the same field."""

        # Typecheck
        if isinstance(other, Share):
            raise TypeError("You can only add shares to shares.")

        # Check if the shares are from the same field
        if self.q != other.q or self.N != other.N:
            raise ValueError(
                "Shares do not belong to the same field or are not of the same length.")


def share_secret(secret: int, num_shares: int) -> List[Share]:
    """Generate shares for a secret."""

    # Generate num_shares - 1 random shares
    random_shares = [Share(101, num_shares) for _ in range(num_shares - 1)]

    # Generate the last share such that the sum of all shares is equal to the secret
    return random_shares + [Share(101, num_shares, secret - sum(share.value for share in random_shares) % 101)]


def reconstruct_secret(shares: List[Share]) -> int:
    """Reconstruct the secret from shares."""

    return sum(share.value for share in shares) % shares[0].q
