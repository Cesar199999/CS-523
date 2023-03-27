"""
Implementation of an SMC client.

MODIFY THIS FILE.
"""
# You might want to import more classes if needed.

from typing import (
    Dict,
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
        self.share_dict: Dict[Secret, Share] = {}

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
    ) -> Union[Share, int]:
        """
        Process an expression using the visitor pattern.
        """
        print("Processing expression: " + str(expr))

        # Process the expression

        if isinstance(expr, Add):
            return self.process_add(expr)

        if isinstance(expr, Mul):
            return self.process_mul(expr)

        if isinstance(expr, Secret):
            return self.process_secret(expr)

        if isinstance(expr, Scalar):
            return expr.value

        raise TypeError("Unknown expression type: " + str(type(expr)))

    def process_mul(self, expr: Mul) -> Union[Share, int]:
        """
        Process a Mul expression.
        """
        [share_x, share_y] = [self.process_expression(arg)
                              for arg in (expr.left, expr.right)]

        # Share multiplication
        if isinstance(share_x, Share) and isinstance(share_y, Share):

            # Get Beaver triplet.
            share_a, share_b, share_c = self.comm.retrieve_beaver_triplet_shares(
                expr.id.hex())

            # Send shares to other parties
            self.comm.publish_message(
                "share: x - a multiplication: " + expr.id.hex() + " " + self.client_id, (share_x - share_a).serialize())
            self.comm.publish_message(
                "share: y - b multiplication: " + expr.id.hex() + " " + self.client_id, (share_y - share_b).serialize())

            # get reconstructed shares from other parties.
            value_x_a = self.retrieve_and_reconstruct(
                "share: x - a multiplication: " + expr.id.hex())
            value_y_b = self.retrieve_and_reconstruct(
                "share: y - b multiplication: " + expr.id.hex())

            # Compute and return the result, add extra term iff this party is the first party.
            return share_c + value_y_b * share_x + value_x_a * share_y - value_x_a * value_y_b * int(self.client_id == min(self.protocol_spec.participant_ids))

        return share_x * share_y

    def process_add(self, expr: Add) -> Union[Share, int]:
        """
        Process an Add expression.
        """

        [share_x, share_y] = [self.process_expression(arg)
                              for arg in (expr.left, expr.right)]

        # Check if the left or right expression are integers and if this party is the first party. Consistently set the
        # first party to be the one with the minimum id.

        if not self.client_id == min(self.protocol_spec.participant_ids) and (isinstance(share_x, Share) or isinstance(share_y, Share)):

            if isinstance(share_x, int):
                return share_y

            if isinstance(share_y, int):
                return share_x

        # Standard share addition.
        return share_x + share_y

    def process_secret(self, expr: Secret) -> Share:
        """
        Process a Secret expression.
        """

        # If the secret has not been shared yet, share it.
        if expr not in self.share_dict:

            # If this party has the secret, share it.
            if expr in self.value_dict:

                # Compute shares.
                shares = share_secret(self.value_dict[expr], len(
                    self.protocol_spec.participant_ids))

                # Send shares to other parties.
                for client_id, share in zip(self.protocol_spec.participant_ids, shares):

                    # Skip if the client is this client.
                    if client_id == self.client_id:
                        self.share_dict[expr] = share
                    else:
                        self.comm.send_private_message(
                            client_id, "share " + expr.id.hex(), share.serialize())
            else:
                # Otherwise, retrieve the share from another party's secret.
                self.share_dict[expr] = Share.deserialize(
                    self.comm.retrieve_private_message("share " + expr.id.hex()))

        # Return the share in the share dictionary.
        return self.share_dict[expr]

    def retrieve_and_reconstruct(self, message: str) -> int:
        """
        Retrieve and reconstruct a share.
        """
        # Retrieve the serialized shares from the server.
        result_shares = list(map(lambda id: self.comm.retrieve_public_message(
            id, message + " " + id), self.protocol_spec.participant_ids))

        # Deserialize the shares and reconstruct the secret.
        return reconstruct_secret(list(map(Share.deserialize, result_shares)))
