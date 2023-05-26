"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

from hashlib import sha256
from typing import Any, List, Set, Tuple, Dict, Union

from serialization import jsonpickle
from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G2, GT, G1Element, G2Element
import math

# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
SecretKey = Tuple[Bn, G1Element, List[Bn]]
PublicKey = Tuple[G1Element, List[G1Element], G2Element, G2Element, List[G2Element]]
Signature = Tuple[G1Element, G1Element]
Attribute = Any
AttributeMap = Dict[int, Attribute]
IssueRequest = Tuple[G1Element, Tuple[G1Element, Tuple[Dict[int, Bn], Bn]]]
BlindSignature = Tuple[Tuple[G1Element, G1Element], AttributeMap]
AnonymousCredential = Tuple[Signature, AttributeMap]
DisclosureProof = Tuple[Tuple[G1Element, G1Element], Tuple[G1Element, G1Element, Dict[int, Bn], Bn], Dict[int, str]]


######################
## SIGNATURE SCHEME ##
######################


def generate_key(
        attributes: List[Attribute]
) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """

    # Generate exponent x and vector y_1, ..., y_n
    x, y = G1.order().random(), [G1.order().random() for _ in attributes]

    # Pick generators g and h
    g, g_tilde = G1.generator(), G2.generator()

    # Compute public key's X values
    X, X_tilde = g ** x, g_tilde ** x

    # Compute public key's Y values
    Y, Y_tilde = [g ** y_i for y_i in y], [g_tilde ** y_i for y_i in y]

    # Compute and return secret and public keys
    return (x, X, y), (g, Y, g_tilde, X_tilde, Y_tilde)


def sign(
        sk: SecretKey,
        msgs: List[bytes]
) -> Signature:
    """ Sign the vector of messages `msgs` """

    # Unpack secret key
    x, _, y = sk

    # Check that the number of messages is equal to the number private attributes
    assert len(msgs) == len(y)

    # Pick generator h
    h = G1.generator()

    # Compute and return signature
    return h, h ** (x + sum(y_i * Bn.from_binary(msg) for y_i, msg in zip(y, msgs)))


def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes]
) -> bool:
    """ Verify the signature on a vector of messages """

    # Unpack public key
    g_tilde, X_tilde, Y_tilde = pk[2:]

    # Unpack signature
    generator, witness = signature

    # Get product
    product = point_product(Y_tilde, bn_from_binary_collection(msgs), X_tilde)

    # Verify signature
    return trivial_check(generator) and generator.pair(product) == witness.pair(g_tilde)


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##


class UserState:
    """ Wrapper class for user state, i.e the random value t and the user attributes

        This class is used to pass state between the `create_issue_request` and
        `obtain_credential` functions. Both t, and user_attributes are class attributes.
    """

    def __init__(self, t: Bn = 0, user_attributes: AttributeMap = {}):
        self.t = t
        self.user_attributes = user_attributes
        self.credentials = None


def create_issue_request(
        pk: PublicKey,
        user_attributes: AttributeMap,
        user_state: UserState
) -> IssueRequest:
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """

    # Unpack public key
    g, Y = pk[:2]

    Y_u = {i: Y[i] for i in user_attributes.keys()}

    # Sample random t and fix it to the class attribute, as well as the user attributes
    user_state.t = G1.order().random()
    user_state.user_attributes = user_attributes

    # Compute commitment
    commitment = point_product(Y_u, bn_from_binary_collection(user_attributes), g ** user_state.t)

    # Compute witness, non-interactive proof pi applying Fiat-Shamir
    pi_proof = get_pi_proof(commitment, pk, user_attributes, user_state.t)

    # Compute and return request
    return commitment, pi_proof


def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
) -> BlindSignature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """

    # Verify request
    if not verify_issue_request(request, pk):
        raise ValueError('Signature request is invalid')

    # If the request is valid, unpack the request and sample random u
    commitment, u = request[0], G1.order().random()

    # Unpack secret and public keys
    X, (g, Y) = sk[1], pk[:2]

    # Get subset of public keys corresponding to the issuer attributes
    Y_I = {i: Y[i] for i in issuer_attributes.keys()}

    # Get Y_i product terms
    product_terms = point_product(Y_I, bn_from_binary_collection(issuer_attributes), X * commitment)

    # Compute and return signature and issuer attributes
    return (g ** u, product_terms ** u), issuer_attributes


def obtain_credential(
        pk: PublicKey,
        response: BlindSignature,
        user_state: UserState
) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """

    # Unpack response and issuer attributes
    (sigma_1, sigma_2), issuer_attributes = response

    # Get full attribute map
    full_attributes: AttributeMap = {**issuer_attributes, **user_state.user_attributes}

    # Compute final signature
    final_signature: Signature = sigma_1, sigma_2 * sigma_1 ** (-user_state.t)

    # Get list of attributes sorted by index
    attributes = [full_attributes[i] for i in sorted(full_attributes.keys())]

    # Verify signature
    if not verify(pk, final_signature, attributes):
        raise ValueError('Signature is invalid')

    # If the signature is valid, return the credential
    return final_signature, full_attributes


def verify_issue_request(request: IssueRequest, pk: PublicKey) -> bool:
    """ Verify that a pi proof is valid for a given commitment and public key """

    # Unpack request
    commitment, (alpha, (s, T)) = request

    # Get generator
    g = pk[0]

    # Get pks for user attributes
    Y_u = {i: pk[1][i] for i in s.keys()}

    # Compute challenge
    challenge = get_challenge(pk, commitment, alpha)

    # Verify that it is a valid pi proof
    return alpha * commitment ** challenge == point_product(Y_u, s, g ** T)


def get_pi_proof(commitment: G1Element, pk: PublicKey, user_attributes: AttributeMap, t: Bn) -> \
        Tuple[G1Element, Tuple[Dict[int, Bn], Bn]]:
    """ Computes pi proof of knowledge of t, (attribute_i)_{i in user_attributes}
        This pi proof is computed using Fiat-Shamir, if n is the number of attributes
        in user_attributes then pi is defined as the tuple (alpha, (s, T)) where

        The constant alpha is then computed as follows:
            Compute a random Z_p element z_i for each attribute_i, and a random z_0
            alpha := g ** z_0 * Y_u_1 ** z_1 * ... * Y_u_n ** z_n

        and s is a tuple of n + 1 elements (s_0, s_1, ..., s_n) where each s_i and T is defined as follows:
            s_i := z_i + c * attribute_i
            T := z_0 + c * t

        where c = H(pk || commitment || alpha)

        To verify that a pi proof (alpha, s) is valid, we need to check that:
            alpha * commitment ** c == g ** T * Y_u_1 ** s_1 * ... * Y_u_n ** s_n

        Args:
            commitment: The commitment to the attributes
            pk: The public key
            user_attributes: The attributes of the user
            t: The class attribute of the user
        Returns:
            A tuple (alpha, (s, T)) where alpha is a G1Element, s is a dictionary of attribute indices to Bn elements
            and T is a Bn element
    """

    # Unpack public key
    g, Y = pk[:2]

    # Filter public key to only include the attributes in the user attributes
    Y_u = {i: Y[i] for i in user_attributes.keys()}

    # Sample z_i's
    z_0 = G1.order().random()
    z = {i: G1.order().random() for i in user_attributes.keys()}

    # Compute alpha
    alpha = point_product(Y_u, z, g ** z_0)

    # Compute challenge
    challenge = get_challenge(pk, commitment, alpha)

    # compute T and s
    T = z_0 + challenge * t
    s = {i: z[i] + challenge * Bn.from_binary(attribute) for i, attribute in user_attributes.items()}

    # Compute and return pi proof
    return alpha, (s, T)


## SHOWING PROTOCOL ##


def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: List[Attribute],
        message: bytes
) -> DisclosureProof:
    """ Create a disclosure proof """

    # Unpack credential
    signature, full_credentials = credential

    # Sample random r and t
    r, t = G1.order().random(), G1.order().random()

    # Compute randomized signature
    randomized_signature: Tuple[G1Element, G1Element] = signature[0] ** r, (signature[1] * signature[0] ** t) ** r

    # Compute pi proof
    proof, indexed_hidden_credentials = get_disclosure_proof(pk, hidden_attributes, full_credentials,
                                                             randomized_signature, t, message)

    # Get disclosed credentials
    indexed_disclosed_credentials = {i: full_credentials[i] for i in
                                     full_credentials.keys() - indexed_hidden_credentials.keys()}

    # Compute and return disclosure proof
    return randomized_signature, proof, indexed_disclosed_credentials


def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        message: bytes
) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """

    # Unpack disclosure proof
    (s1, s2), (commit, alpha, s, T), indexed_disclosed_attributes = disclosure_proof

    # Unpack public key
    g_tilde, X_tilde, Y_tilde = pk[2:]

    # Get challenge
    challenge = get_disclosure_challenge(pk, (s1, s2), commit, message, alpha)

    # Pair keys
    disclosed_paired_terms = {i: s1.pair(y) for i, y in enumerate(Y_tilde) if i in indexed_disclosed_attributes.keys()}
    hidden_paired_terms = {i: s1.pair(y) for i, y in enumerate(Y_tilde) if i in s.keys()}

    # Disclosed terms
    exponents = {i: -b for i, b in bn_from_binary_collection(indexed_disclosed_attributes).items()}
    disclosed_terms_product = point_product(disclosed_paired_terms, exponents, s2.pair(g_tilde))

    # Hidden terms
    hidden_terms_product = point_product(hidden_paired_terms, s, s1.pair(g_tilde) ** T)

    # Verify that it is a valid disclosure proof
    return trivial_check(s1) and \
        commit ** challenge * alpha == hidden_terms_product and \
        s1.pair(X_tilde) * commit == disclosed_terms_product


def get_disclosure_proof(pk: PublicKey, hidden_attributes: List[Attribute], full_credentials: AttributeMap,
                         randomized_signature: Signature, t: Bn, message: bytes) -> \
        Tuple[Tuple[G1Element, G1Element, Dict[int, Bn], Bn], Dict[int, Attribute]]:
    """ Compute disclosure proof for showing protocol

    Args:
        pk: g, (Y_1, ..., Y_n), g_tilde, X_tilde, (Y_tilde_1, ..., Y_tilde_n)
        hidden_attributes: The attributes hidden to the verifier
        full_credentials: The full credentials of the user
        randomized_signature: (s1, s2)
        t: random signature exponent
        message: The message to be signed

    Returns:
        A tuple ((commit, alpha, s, T), indexed_hidden_attributes) where commit is a G1Element, alpha is a G1Element,
        s is a dictionary of attribute indices to Bn elements, T is a Bn element and indexed_hidden_attributes is a
        dictionary of attribute indices to attributes.

        The tuple is a valid disclosure proof for the showing protocol. Namely, it is a valid proof of knowledge:

        PK{ (t, (attribute_i)_{i in hidden_attributes}) :
            s2.pair(g_tilde) * prod(s_1.pair(Y_tilde_i) ** (-a_i) for i in disclosed_attributes)/s1.pair(X_tilde)
            is equal to
            s1.pair(X_tilde) ** t * prod(s_1.pair(Y_tilde_i) ** (a_i) for i in hidden_attributes)
        }

    """

    # Index hidden attributes with their index in the full credentials
    indexed_hidden_attributes: Dict[int, Attribute] = {i: attribute for i, attribute in full_credentials.items() if
                                                       attribute in hidden_attributes}

    # Unpack public key
    g_tilde, X_tilde, Y_tilde = pk[2:]

    # Unpack randomized signature
    s1, s2 = randomized_signature

    # Compute terms in the pairings
    Y_pair_terms = {i: s1.pair(Y_tilde[i]) for i in indexed_hidden_attributes.keys()}

    # Sample z_i's
    z_prime = G1.order().random()
    z = {i: G1.order().random() for i in indexed_hidden_attributes.keys()}

    # Compute commitment
    commit = point_product(Y_pair_terms, bn_from_binary_collection(indexed_hidden_attributes), s1.pair(g_tilde) ** t)

    # Compute alpha
    alpha = point_product(Y_pair_terms, z, s1.pair(g_tilde) ** z_prime)

    # Compute challenge
    challenge = get_disclosure_challenge(pk, randomized_signature, commit, message, alpha)

    # Compute term for t
    T: Bn = z_prime + challenge * t

    # compute s_i's
    s = {i: z[i] + challenge * Bn.from_binary(attribute) for i, attribute in indexed_hidden_attributes.items()}

    # Compute and return pi proof
    return (commit, alpha, s, T), indexed_hidden_attributes


############################################ HELPER FUNCTIONS #########################################################

def point_product(points: Union[Dict[int, G1Element], List[G1Element]],
                  exponents: Union[Dict[int, Bn], List[Bn]] = None, shift: Bn = None) -> G1Element:
    """ Compute the product of points raised to exponents multiplied by shift """

    # If no exponents are given, set them to 1
    if exponents is None:
        if isinstance(points, Dict):
            exponents = {i: Bn(1) for i in points.keys()}
        else:
            exponents = [Bn(1) for _ in points]

    # If no shift is given, set it to 1
    if shift is None:
        shift = G1.neutral_element()

    # Check that the number of points and exponents are the same
    assert len(points) == len(exponents)

    # Get terms
    terms = [points[key] ** exponents[key] for key in points.keys()] if isinstance(points, Dict) \
        else [point ** exponent for point, exponent in zip(points, exponents)]

    # Return product
    return math.prod(terms, start=shift)


def bn_from_binary_collection(binary_collection: Union[Dict[int, str], List[str]]) -> Union[Dict[int, Bn], List[Bn]]:
    """ Convert a collection of binary strings to a collection of Bn elements """

    return {key: Bn.from_binary(binary) for key, binary in binary_collection.items()} if isinstance(binary_collection,
                                                                                                    Dict) \
        else [Bn.from_binary(binary) for binary in binary_collection]


def trivial_check(point: G1Element) -> bool:
    """ Check that the point is not the neutral element """

    return point != G1.neutral_element()


def get_challenge(pk: PublicKey, commitment: G1Element, alpha: G1Element) -> Bn:
    """ Compute challenge using Fiat-Shamir

    We use the hash function sha256 to compute the challenge.

        c = sha256(pk || commitment || Y_u || alpha)
    """

    # Pickle and hash the concatenated elements
    return pickle_and_hash((pk, commitment, alpha))


def get_disclosure_challenge(
        pk: PublicKey,
        randomized_signature: Signature,
        commitment: G1Element,
        message: bytes,
        alpha: G1Element
) -> Bn:
    """ Compute challenge for the showing protocol

        Returns:
            A challenge c := H(pk || randomized_signature || commitment || message || alpha)
    """

    # Pickle and hash the concatenated elements
    return pickle_and_hash((pk, randomized_signature, commitment, message, alpha))


def pickle_and_hash(obj: Any) -> Bn:
    """ Pickle and hash an object

    Args:
        obj: The object to be pickled and hashed

    Returns:
        The hash of the pickled object
    """

    # Pickle object
    pickled = jsonpickle.encode(obj)

    # Return hash of pickled object
    return Bn.from_hex(sha256(pickled.encode("utf-8")).hexdigest())
