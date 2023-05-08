"""
Classes that you need to complete.
"""

from binascii import hexlify
from typing import Any, Dict, List, Union, Tuple
from credential import *

# Optional import
from serialization import jsonpickle

# Type aliases
State = Any


class Server:
    """Server"""

    # Maps subscriptions to their index
    subscriptionMap: Dict[str, int]

    def __init__(self):
        """
        Server constructor.
        """

        self.users_issuer_attributes = {}

    @staticmethod
    def generate_ca(
        subscriptions: List[str]
    ) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's public information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """

        # Issuer subscription map
        Server.subscriptionMap = {subscription: i for i,
                                  subscription in enumerate(subscriptions)}

        # Generate key pair
        sk, pk = generate_key(subscriptions)

        # return the server's secret key and public information
        return jsonpickle.encode(sk), jsonpickle.encode(pk)

    def process_registration(
        self,
        server_sk: bytes,
        server_pk: bytes,
        issuance_request: bytes,
        username: str,
        subscriptions: List[str]
    ) -> bytes:
        """ Registers a new account on the server.

        Args:
            server_sk: the server's secret key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes


        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """

        # Deserialize the server's secret and public keys
        sk: SecretKey = jsonpickle.decode(server_sk)
        pk: PublicKey = jsonpickle.decode(server_pk)

        # Deserialize the issuance request
        issue_request: IssueRequest = jsonpickle.decode(issuance_request)

        # Issuer subscription map, maps issuer chosen attributes to their index
        issuer_attributes = {i: hexlify(G1.order().random().binary(
        )) for i in set(Server.subscriptionMap.values()) - issue_request[1][2]}

        # Remember the issuer attributes
        self.users_issuer_attributes[username] = issuer_attributes

        # Sign and return the issue request
        signed_issue_request: BlindSignature = sign_issue_request(
            sk, pk, issue_request, issuer_attributes)

        # Return the signed issue request
        return jsonpickle.encode(signed_issue_request)

    def check_request_signature(
        self,
        server_pk: bytes,
        message: bytes,
        revealed_attributes: List[str],
        signature: bytes
    ) -> bool:
        """ Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """

        # Verify the signature
        return verify_disclosure_proof(jsonpickle.decode(server_pk),  jsonpickle.decode(
            signature, keys=True), message)


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """
        self.user_state = UserState()
        self.username = None
        self.secret_key = G1.order().random()
        self.anonymous_credential = None

    def prepare_registration(
        self,
        server_pk: bytes,
        username: str,
        subscriptions: List[str]
    ) -> Tuple[bytes, State]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """

        # Deserialize the server's public key
        pk: PublicKey = jsonpickle.decode(server_pk)

        # Get random keys for each subscription
        user_attributes = {Server.subscriptionMap[subscription]: hexlify(G1.order().random().binary())
                           for subscription in subscriptions}

        # Create the issue request
        issue_request: IssueRequest = create_issue_request(
            pk, user_attributes, self.user_state)

        # Return the issue request and the private state
        return jsonpickle.encode(issue_request), self.user_state

    def process_registration_response(
        self,
        server_pk: bytes,
        server_response: bytes,
        private_state: State
    ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """

        # Deserialize the server's public key
        pk: PublicKey = jsonpickle.decode(server_pk)

        # Deserialize the server's response, int keys are deserialized as strings
        signed_issue_request: BlindSignature = jsonpickle.decode(
            server_response)

        issuer_attributes = {
            int(k): v for k, v in signed_issue_request[1].items()}

        # Create the credential
        credential: AnonymousCredential = obtain_credential(
            pk, (signed_issue_request[0], issuer_attributes), private_state)

        # Serialize the credential
        return jsonpickle.encode(credential, keys=True)

    def sign_request(
        self,
        server_pk: bytes,
        credentials: bytes,
        message: bytes,
        types: List[str]
    ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """

        # Deserialize the server's public key
        pk: PublicKey = jsonpickle.decode(server_pk)

        # Deserialize the credential
        credential: AnonymousCredential = jsonpickle.decode(
            credentials, keys=True)

        # Unpack the credential
        full_attributes = credential[1]

        # Get subscription indices
        subscription_indices = set(Server.subscriptionMap[t] for t in types)

        # Get hidden attributes
        hidden_attributes = list(
            map(int, set(full_attributes.keys()) - subscription_indices))

        # Sign the message
        disclosure_proof: DisclosureProof = create_disclosure_proof(
            pk, credential, hidden_attributes, message)

        # Return the signature
        return jsonpickle.encode(disclosure_proof, keys=True)
