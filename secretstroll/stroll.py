"""
Classes that you need to complete.
"""

from binascii import hexlify
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

        # Issuer subscription map, maps attributes to their index
        subscriptionMap = {subscription: i for i, subscription in enumerate(subscriptions)}
        subscriptionMap["password"] = len(subscriptions)

        # Generate key pair
        sk, pk = generate_key(subscriptions + ["password"])

        # return the server's secret key and public information
        return bytes(jsonpickle.encode(sk), 'utf-8'), \
            bytes(jsonpickle.encode((pk, subscriptionMap), keys=True), 'utf-8')

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

        # Deserialize the server's public key and subscription map
        tmp: Tuple[PublicKey, Dict[str, int]] = jsonpickle.decode(server_pk.decode('utf-8'), keys=True)
        pk, subscriptionMap = tmp

        # Deserialize the server's secret key
        sk: SecretKey = jsonpickle.decode(server_sk.decode('utf-8'))

        # Deserialize the issuance request
        issue_request: IssueRequest = jsonpickle.decode(issuance_request.decode('utf-8'), keys=True)

        # Get the user's attributes indices
        user_attributes_indices = issue_request[1][1][0].keys()

        # Check that the password is in the request
        if subscriptionMap["password"] not in user_attributes_indices:
            raise ValueError("Password not in request")

        # Check that the username is in the request
        if subscriptionMap["username"] not in user_attributes_indices:
            raise ValueError("Username not in request")

        # Issuer subscription map, maps issuer chosen attributes to their index
        issuer_attributes = {i: hexlify(G1.order().random().binary()) for i in
                             set(subscriptionMap.values()) - user_attributes_indices}

        # Sign and return the issue request
        signed_issue_request: BlindSignature = sign_issue_request(
            sk, pk, issue_request, issuer_attributes)

        # Remember the issuer attributes
        self.users_issuer_attributes[username] = issuer_attributes

        # Return the signed issue request
        return bytes(jsonpickle.encode(signed_issue_request), 'utf-8')

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

        # Deserialize the server's public key and subscription map
        pk: PublicKey = jsonpickle.decode(server_pk.decode('utf-8'), keys=True)[0]

        # Verify the signature
        return verify_disclosure_proof(pk, jsonpickle.decode(signature.decode('utf-8'), keys=True), message)


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """
        self.user_state = UserState()
        self.username = None
        self.password = hexlify(G1.order().random().binary())
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

        # Remember the username
        self.username = username

        # Deserialize the server's public key and subscription map
        tmp: Tuple[PublicKey, Dict[str, int]] = jsonpickle.decode(server_pk.decode('utf-8'), keys=True)
        pk, subscriptionMap = tmp

        # Get random keys for each subscription
        user_attributes = {subscriptionMap[subscription]: subscription.encode('utf-8')
                           for subscription in subscriptions}
        user_attributes[subscriptionMap["username"]] = username.encode('utf-8')
        user_attributes[subscriptionMap["password"]] = self.password

        # Create the issue request
        issue_request: IssueRequest = create_issue_request(pk, user_attributes, self.user_state)

        # Return the issue request and the private state
        return bytes(jsonpickle.encode(issue_request, keys=True), 'utf-8'), self.user_state

    def process_registration_response(
            self,
            server_pk: bytes,
            server_response: bytes,
            private_state: State
    ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk: a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """

        # Deserialize the server's public key and subscription map
        tmp: Tuple[PublicKey, Dict[str, int]] = jsonpickle.decode(server_pk.decode('utf-8'), keys=True)
        pk, subscriptionMap = tmp

        # Deserialize the server's response, int keys are deserialized as strings
        signed_issue_request: BlindSignature = jsonpickle.decode(
            server_response.decode('utf-8'))

        issuer_attributes = {
            int(k): v for k, v in signed_issue_request[1].items()}

        # Create the credential
        credential: AnonymousCredential = obtain_credential(
            pk, (signed_issue_request[0], issuer_attributes), private_state)

        # Serialize the credential
        return bytes(jsonpickle.encode(credential, keys=True), 'utf-8')

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

        # Deserialize the server's public key and subscription map
        tmp: Tuple[PublicKey, Dict[str, int]] = jsonpickle.decode(server_pk.decode('utf-8'), keys=True)
        pk, subscriptionMap = tmp

        # Deserialize the credential
        credential: AnonymousCredential = jsonpickle.decode(credentials.decode('utf-8'), keys=True)

        # Unpack the credential
        full_attributes = credential[1]

        # Check that the password is not in the request
        if "password" in types:
            raise ValueError("Password cannot be revealed")

        # Get subscription indices
        subscription_indices = set(subscriptionMap[t] for t in types)

        # Get hidden attributes
        hidden_attributes = list(
            map(int, set(full_attributes.keys()) - subscription_indices))

        # Sign the message
        disclosure_proof: DisclosureProof = create_disclosure_proof(
            pk, credential, hidden_attributes, message)

        # Return the signature
        return bytes(jsonpickle.encode(disclosure_proof, keys=True), 'utf-8')
