"""
Secret sharing scheme.
"""
from __future__ import annotations
import random
from typing import List, Union

import json
import operator
import petrelic.bn as bn


class UniquePrime():
    """ Wrapper class to fix a unique prime number at runtime.
        This is used to ensure that the same prime number is used for all shares.
    """
    # Value must be changed to 1024 bits in order to run the benchmarks.
    __unique_prime = bn.Bn.get_prime(1024).int(
    )  # After 1024 bits a Segmentation Fault occurs.

    # Singleton pattern.
    def __init__(self):
        pass

    def get_unique_prime(self):
        """ Returns the unique prime number. """
        return self.__unique_prime


class Share:
    """
    A secret share in a finite field.
    """

    # Initialize a share with a value and a prime number.
    def __init__(self, value: int = None):
        """Initialize a share with a value and a prime number.

        Args:
            value (int): The value of the share. Defaults to a random integer in the finite field.
            order (int): The prime number. Defaults to a random prime of 256 bits.
        """
        self.value = value % UniquePrime().get_unique_prime() if value else random.randint(
            0, UniquePrime().get_unique_prime() - 1)

    def __repr__(self):

        # Helps with debugging.
        return f"Share({self.value})"

    def __add__(self, other):

        # Share and scalar addition.
        return self.compute_operation(other, operator.add)

    def __radd__(self, other):

        # Scalar and share addition.
        return self.__add__(other)

    def __sub__(self, other):

        # Share and scalar subtraction.
        return self.compute_operation(other, operator.sub)

    def __rsub__(self, other):

        # Scalar and share subtraction.
        return self.__sub__(other)

    def __mul__(self, other):

        # Share and scalar multiplication.
        return self.compute_operation(other, operator.mul)

    def __rmul__(self, other):

        # Scalar and share multiplication.
        return self.__mul__(other)

    def serialize(self):
        """Generate a representation suitable for passing in a message."""

        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=2)

    @staticmethod
    def deserialize(serialized) -> Share:
        """Restore object from its serialized representation."""

        return Share(**json.loads(serialized))

    def compute_operation(self, other: Union[int, Share], operation: operator) -> Share:
        """Compute the operation between two shares."""

        # Now in one line:
        return Share(operation(self.value, other.value if isinstance(other, Share) else other))


def share_secret(secret: int, num_shares: int) -> List[Share]:
    """Generate shares for a secret."""

    # Generate num_shares - 1 random shares.
    random_shares = [Share() for _ in range(num_shares - 1)]

    # Generate the last share such that the sum of all shares is equal to the secret.
    first_share = Share(secret - sum(share.value for share in random_shares))

    return random_shares + [first_share]


def reconstruct_secret(shares: List[Share]) -> int:
    """Reconstruct the secret from shares."""

    return sum(share.value for share in shares) % UniquePrime().get_unique_prime()
