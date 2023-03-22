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

        # Get the share
        share = self.process_expression(self.protocol_spec.expr)

        # Send the share to the server
        self.comm.publish_message(
            "final share: " + str(self.client_id), share.serialize())

        # Get the result from the server
        return reconstruct_secret([Share.deserialize(self.comm.retrieve_public_message(other_client_id, "final share: " + str(other_client_id))) for other_client_id in self.protocol_spec.participant_ids])

    def process_expression(
        self,
        expr: Expression
    ) -> Share:
        """
        Process an expression using the visitor pattern.
        """
        print("Processing expression: " + str(expr))

        # Process the expression
        if isinstance(expr, Secret):
            return self.process_secret(expr)

        elif isinstance(expr, Scalar):
            return expr.value

        elif isinstance(expr, Add):
            return self.process_add(expr)

        elif isinstance(expr, Mul):
            return self.process_mul(expr)
        
        elif isinstance(expr, Share):
            return expr

    def process_mul(self, expr: Expression) -> Share:
        """
        Process a Mul expression.
        """
        # share multiplication
        if isinstance(expr.left, Share) and isinstance(expr.right, Share):
            beaver = self.comm.retrieve_beaver_triplet_shares(expr.id)
            d = Share(101, value=self.process_expression(expr.left)-beaver[0])
            self.comm.publish_message(d)
            e = Share(101, value=self.process_expression(expr.right)-beaver[1])
            self.comm.publish_message(e)
            sv = d*e + d*beaver[1] + e*beaver[0] + beaver[2]
            return sv

        return self.process_expression(expr.left) * self.process_expression(expr.right)

    def process_add(self, expr) -> Share:
        """
        Process an Add expression.
        """

        # Scalar addition
        is_first_party = (self.client_id == min(
            self.protocol_spec.participant_ids))

        if isinstance(expr.left, int) and not is_first_party:
            return self.process_expression(expr.right)

        elif isinstance(expr.right, int) and not is_first_party:
            return self.process_expression(expr.left)

        return self.process_expression(expr.left) + self.process_expression(expr.right)

    def process_secret(self, expr: Secret) -> Share:
        """
        Process a Secret expression.
        """
        # Send shares
        if expr in self.value_dict:
            shares = share_secret(self.value_dict[expr], len(
                self.protocol_spec.participant_ids))
            for client_id, share in zip(self.protocol_spec.participant_ids, shares):
                if client_id == self.client_id:
                    result = share
                    continue
                self.comm.send_private_message(
                    client_id, "share " + str(expr.id), share.serialize())
        else:
            # Receive share
            result = Share.deserialize(
                self.comm.retrieve_private_message("share " + str(expr.id)))

        # Return the result
        return result
