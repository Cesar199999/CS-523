"""
Implementation of an SMC client.

MODIFY THIS FILE.
"""
# You might want to import more classes if needed.

from typing import (
    Dict
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

        # Get the share after multiparty computation.
        share = self.process_expression(self.protocol_spec.expr)

        # Send the share to the server.
        self.comm.publish_message(
            "final share: " + self.client_id, share.serialize())

        # Retrieve the serialized shares from the server.
        result_shares = list(map(lambda id: self.comm.retrieve_public_message(
            id, "final share: " + id), self.protocol_spec.participant_ids))

        # Deserialize the shares and reconstruct the secret.
        return reconstruct_secret(list(map(Share.deserialize, result_shares)))

    def process_expression(
        self,
        expr: Expression
    ) -> Share:
        """
        Process an expression using the visitor pattern.
        """
        print("Processing expression: " + str(expr))

        # Process the expression

        if isinstance(expr, Add):
            return self.process_add(expr)

        elif isinstance(expr, Mul):
            return self.process_mul(expr)

        elif isinstance(expr, Secret):
            return self.process_secret(expr)

        elif isinstance(expr, Share):
            return expr.value

        elif isinstance(expr, Scalar):
            return expr.value

    def process_mul(self, expr: Expression) -> Share:
        """
        Process a Mul expression.
        """
        # Secret multiplication
        if isinstance(expr.left, Secret) and isinstance(expr.right, Secret):

            # Get Beaver triplet
            beaver_a, beaver_b, beaver_c = self.comm.retrieve_beaver_triplet_shares(
                expr.id.hex())

            # Compute left and right shares
            share_d = Share(self.process_expression(
                expr.left) - beaver_a)
            share_e = Share(self.process_expression(
                expr.right) - beaver_b)

            # Send shares to other parties
            self.comm.publish_message(
                "share: d " + expr.id.hex(), share_d.serialize())
            self.comm.publish_message(
                "beaver: e " + expr.id.hex(), share_e.serialize())

            for client in self.protocol_spec.participant_ids:
                if client != self.client_id:
                    share_d += Share.deserialize(self.comm.retrieve_public_message(
                        client, "share: d " + expr.id.hex()))
                    share_d += Share.deserialize(self.comm.retrieve_public_message(
                        client, "share: e " + expr.id.hex()))

            return share_d * share_e + share_d * beaver_b + share_e * beaver_a + beaver_c

        return self.process_expression(expr.left) * self.process_expression(expr.right)

    def process_add(self, expr) -> Share:
        """
        Process an Add expression.
        """

        # Scalar addition: Consistently set the first party to be the one with the minimum id.
        is_first_party = (self.client_id == min(
            self.protocol_spec.participant_ids))

        # Check if the left or right expression is a scalar.
        if isinstance(expr.left, Scalar) and not is_first_party:
            return self.process_expression(expr.right)

        elif isinstance(expr.right, Scalar) and not is_first_party:
            return self.process_expression(expr.left)

        # Standard addition otherwise.
        return self.process_expression(expr.left) + self.process_expression(expr.right)

    def process_secret(self, expr: Secret) -> Share:
        """
        Process a Secret expression.
        """
        # If this party has the secret, share it.
        if expr in self.value_dict:

            # Compute shares.
            shares = share_secret(self.value_dict[expr], len(
                self.protocol_spec.participant_ids))

            # Send shares to other parties.
            for client_id, share in zip(self.protocol_spec.participant_ids, shares):

                # Skip if the client is this client.
                if client_id == self.client_id:
                    result = share
                else:
                    self.comm.send_private_message(
                        client_id, "share " + expr.id.hex(), share.serialize())
        else:
            # Otherwise, retrieve the share from another party's secret.
            result = Share.deserialize(
                self.comm.retrieve_private_message("share " + expr.id.hex()))

        # Return the resulting share.
        return result
