"""
Implementation of an SMC client.

MODIFY THIS FILE.
"""
# You might want to import more classes if needed.

import collections
import json
from typing import (
    Dict,
    Set,
    Tuple,
    Union
)

from communication import Communication
from expression import (
    Expression,
    Secret,
    Scalar,
    Add,
    Mul,
)
from protocol import ProtocolSpec
from secret_sharing import (
    reconstruct_secret,
    share_secret,
    Share,
)

# Feel free to add as many imports as you want.


class SMCParty:
    """
    A client that executes an SMC protocol to collectively compute a value of an expression together
    with other clients.

    Attributes:
        client_id: Identifier of this client
        server_host: hostname of the server
        server_port: port of the server
        protocol_spec (ProtocolSpec): Protocol specification
        value_dict (dict): Dictionary assigning values to secrets belonging to this client.
    """

    def __init__(
        self,
        client_id: str,
        server_host: str,
        server_port: int,
        protocol_spec: ProtocolSpec,
        value_dict: Dict[Secret, int]
    ):
        self.comm = Communication(server_host, server_port, client_id)

        self.client_id = client_id
        self.protocol_spec = protocol_spec
        self.value_dict = value_dict

    def run(self) -> int:
        """
        The method the client use to do the SMC.
        """

        # Get the expression to evaluate
        expr = self.protocol_spec.expr

        clients = self.protocol_spec.participant_ids

        # Process the expression
        for secret, value in self.value_dict.items():

            # Partition the secret into shares
            shares = share_secret(value, len(clients))

            # For each client
            for i, client in enumerate(clients):

                # Check if the client is not the current client
                if client != self.client_id:

                    # Send the share to the server
                    self.comm.send_private_message(
                        client,
                        "from " + self.client_id + " to " + client,
                        shares[i].serialize()
                    )
        shares = []

        # Receive the shares from the server
        for i, client in enumerate(clients):

            # Check if the client is not the current client
            if client != self.client_id:

                # Receive the share from the server
                share = self.comm.retrieve_private_message(
                    "from " + client + " to " + self.client_id
                )

                # Deserialize the share
                shares.append(Share.deserialize(share))

        # Reconstruct the secret
        result = reconstruct_secret(shares)

        print("Result: " + str(result))

        # Send the result to the server
        return result

    def process_expression(
        self,
        expr: Expression
    ):
        """
        Process an expression using the visitor pattern.
        """

        if isinstance(expr, Add):
            return self.process_add(expr)

        elif isinstance(expr, Mul):
            return self.process_mul(expr)

        elif isinstance(expr, Secret):
            return self.process_secret(expr)

        elif isinstance(expr, Scalar):
            return self.process_scalar(expr)

        else:
            raise ValueError("Unknown expression type.")

    def process_add(self, expr: Add) -> int:
        """
        Process an Add expression.
        """

        # Process the left and right subexpressions
        left = self.process_expression(expr.left)
        right = self.process_expression(expr.right)

        # Add the results
        return left + right

    def process_mul(self, expr: Mul) -> int:
        """
        Process a Mul expression.
        """

        # Process the left and right subexpressions
        left = self.process_expression(expr.left)
        right = self.process_expression(expr.right)

        # Multiply the results
        return left * right

    def process_secret(self, expr: Secret) -> int:
        """
        Process a Secret expression.
        """

        # Get the value of the secret
        return self.value_dict[expr]

    def process_scalar(self, expr: Scalar) -> int:
        """
        Process a Scalar expression.
        """

        # Get the value of the scalar
        return expr.value
