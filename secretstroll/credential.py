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
from typing import Any, List, Set, Tuple, Dict

from serialization import jsonpickle
from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G2, GT, G1Element, G2Element
import math


# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
SecretKey = Tuple[Bn, G1Element, List[Bn]]
PublicKey = Tuple[G1Element, List[G1Element],
                  G2Element, G2Element, List[G2Element]]
Signature = Tuple[G1Element, G1Element]
Attribute = Any
AttributeMap = Dict[int, Attribute]
IssueRequest = Tuple[G1Element, Tuple[G1Element, List[Bn], Set[int]]]
BlindSignature = Tuple[Tuple[G1Element, G1Element], AttributeMap]
AnonymousCredential = Tuple[Signature, AttributeMap]
DisclosureProof = Any


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

    # Get Y vector
    terms = [Y_i ** Bn.from_binary(msg) for Y_i, msg in zip(Y_tilde, msgs)]

    # Verify signature
    return False if generator == G1.neutral_element() else \
        generator.pair(math.prod(terms, start=X_tilde)
                       ) == witness.pair(g_tilde)


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

    Y_u = [Y[i] for i in user_attributes.keys()]

    # Sample random t and fix it to the class attribute, as well as the user attributes
    user_state.t = G1.order().random()
    user_state.user_attributes = user_attributes

    # Product terms
    terms = [Y_i ** Bn.from_binary(attribute)
             for Y_i, attribute in zip(Y_u, user_attributes.values())]

    # Compute commitment
    commitment: G1Element = math.prod(terms, start=g ** user_state.t)

    # Compute witness, non-interactive proof pi applying Fiat-Shamir
    pi_proof: Tuple[G1Element, List[Bn], Set[int]] = get_pi_proof(
        commitment, pk, user_attributes, user_state.t)

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
    Y_I = [Y[i] for i in issuer_attributes.keys()]

    # Get Y_i product terms
    terms = [Y_i ** Bn.from_binary(attribute)
             for Y_i, attribute in zip(Y_I, issuer_attributes.values())]

    # Compute and return signature and issuer attributes
    return (g ** u, math.prod(terms, start=X * commitment) ** u), issuer_attributes


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
    full_attributes: AttributeMap = {
        **issuer_attributes, **user_state.user_attributes}

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
    commitment, (alpha, s, user_attributes_indices) = request

    # Get generator
    g = pk[0]

    # Get pks for user attributes
    Y_u = [pk[1][i] for i in user_attributes_indices]

    # Compute c
    c = get_challenge(commitment, Y_u, alpha)

    # Product terms
    terms = [Y_i ** s_i for Y_i, s_i in zip(Y_u, s[1:])]

    # Verify that it is a valid pi proof
    return alpha * commitment ** c == math.prod(terms, start=g ** s[0])


def get_pi_proof(commitment: G1Element, pk: PublicKey, user_attributes: AttributeMap, t: Bn) -> Tuple[G1Element, List[Bn], Set[int]]:
    """ Compute pi proof of knowledge of t, (attribute_i)_{i in user_attributes}

        This pi proof is computed using Fiat-Shamir, if n is the number of attributes
        in user_attributes then pi is defined as the tuple (alpha, s, Y_u) where
        Y_u is a tuple of n elements (Y_u_1, ..., Y_u_n) where each Y_u_i corresponds
        to the attribute_i public key.

        The constant alpha is then computed as follows:

            Compute a random Z_p element z_i for each attribute_i, and a random z_0

            alpha := g ** z_0 * Y_u_1 ** z_1 * ... * Y_u_n ** z_n

        and s is a tuple of n + 1 elements (s_0, s_1, ..., s_n) where each s_i is defined as follows:

            s_i := z_i + c * attribute_i

        and s_0 := z_0 + c * t

        where c = H(commitment, Y_u, alpha)

        ====================================

        To verify that a pi proof (alpha, s) is valid, we need to check that:

            alpha * commitment ** c == g ** s_0 * Y_u_1 ** s_1 * ... * Y_u_n ** s_n
    """

    # Unpack public key
    g, Y = pk[:2]

    # Filter public key to only include the attributes in the user attributes
    Y_u = [Y[i] for i in user_attributes.keys()]

    # Sample z_i's
    z = [G1.order().random() for _ in range(len(user_attributes) + 1)]

    # Compute alpha
    alpha = math.prod(
        [Y_i ** z_i for Y_i, z_i in zip(Y_u, z[1:])], start=g ** z[0])

    # Compute challenge
    challenge = get_challenge(commitment, Y_u, alpha)

    # compute s
    s = [z[0] + challenge * t] + [z_i + challenge *
                                  Bn.from_binary(attribute) for z_i, attribute in zip(z[1:], user_attributes.values())]

    # Compute and return pi proof
    return alpha, s, set(user_attributes.keys())


def get_challenge(pk: PublicKey, commitment: G1Element, alpha: G1Element) -> Bn:
    """ Compute challenge using Fiat-Shamir

    We use the hash function sha256 to compute the challenge.

        c = sha256(commitment | public_key)
    """

    # Compute and return challenge
    return Bn.from_binary(sha256((jsonpickle.encode(commitment) + jsonpickle.encode(pk) + jsonpickle.encode(alpha)).encode('utf-8')).digest())

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
    randomized_signature = signature[0] ** r, (signature[1]
                                               * signature[0] ** t) ** r

    # Compute pi proof
    proof, indexed_hidden_credentials = get_disclosure_proof(
        pk, hidden_attributes, full_credentials, randomized_signature, t, message)

    # Get disclosed credentials
    indexed_disclosed_credentials = {
        i: full_credentials[i] for i in full_credentials.keys() - indexed_hidden_credentials.keys()}

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

    # TODO: SAVE DISCLOSED ATTRIBUTES
    # TODO: INCORPORATE G_TILDE and S2 INTO DISCLOSURE PROOF

    # Unpack disclosure proof
    (s1, s2), (commit, alpha, s, T), indexed_disclosed_attributes = disclosure_proof

    # Unpack public key
    g_tilde, X_tilde, Y_tilde = pk[2:]

    # Get challenge
    challenge = get_disclosure_challenge(
        pk, (s1, s2), commit, message, alpha)

    # Get paired terms
    disclosed_terms = [s1.pair(Y_tilde[i]) ** (-Bn.from_binary(attribute)) for i,
                       attribute in indexed_disclosed_attributes.items()]

    # Hidden terms
    hidden_terms = [s1.pair(Y_tilde[i]) ** s_i for i, s_i in s.items()]

    # Verify that it is a valid disclosure proof
    return s1 != G1.neutral_element() and commit ** challenge * alpha == math.prod(hidden_terms, start=s1.pair(g_tilde) ** T) and math.prod(disclosed_terms, start=s2.pair(g_tilde)) == s1.pair(X_tilde) * commit


def get_disclosure_proof(pk: PublicKey, hidden_attributes: List[Attribute], full_credentials: AttributeMap, randomized_signature: Signature, t: Bn, message: bytes) -> Tuple[G1Element, Tuple[G1Element, List[Bn], Set[int]]]:
    """ Compute disclosure proof for showing protocol

    g, (Y_1, ..., Y_n), g_tilde, X_tilde, (Y_tilde_1, ..., Y_tilde_n) = pk
    s1, s2 = randomized_signature
    Then the zero knowledge proof is defined as follows:

    PK{(t, (attribute_i)_{i in hidden_attributes}) : s2.pair(g_tilde) * prod(s_1.pair(Y_tilde_i) ** (-a_i)
        for i in disclosed_attributes)/s1.pair(X_tilde)  == s1.pair(X_tilde) ** t * prod(s_1.pair(Y_tilde_i) ** (a_i) for i in hidden_attributes) }

    """

    # Index hidden attributes with their index in the full credentials
    indexed_hidden_attributes = {i: attribute for i, attribute in full_credentials.items(
    ) if attribute in hidden_attributes}

    # Unpack public key
    g_tilde, X_tilde, Y_tilde = pk[2:]

    # Unpack randomized signature
    s1, s2 = randomized_signature

    # Compute terms in the pairings
    Y_pair_terms = {i: s1.pair(Y_tilde[i])
                    for i in full_credentials.keys()}

    # Compute hidden terms
    hidden_terms = [Y_pair_terms[i] ** Bn.from_binary(
        attribute) for i, attribute in indexed_hidden_attributes.items()]

    # Sample z_i's
    z = {i: G1.order().random() for i in indexed_hidden_attributes.keys()}
    z_prime = G1.order().random()

    # Compute commitment
    commit = math.prod(hidden_terms, start=s1.pair(g_tilde) ** t)

    # Compute alpha
    alpha = math.prod([Y_pair_terms[i] ** z[i]
                      for i in indexed_hidden_attributes.keys()], start=s1.pair(g_tilde) ** z_prime)

    # Compute challenge
    challenge = get_disclosure_challenge(
        pk, randomized_signature, commit, message, alpha)

    # compute s
    s = {i: z[i] + challenge * Bn.from_binary(attribute)
         for i, attribute in indexed_hidden_attributes.items()}

    # Compute term for t
    T = z_prime + challenge * t
    # Compute and return pi proof
    return (commit, alpha, s, T), indexed_hidden_attributes


def get_disclosure_challenge(
    pk: PublicKey,
    randomized_signature: Signature,
    commitment: G1Element,
    message: bytes,
    alpha: G1Element
) -> Bn:
    """ Compute challenge for showing protocol """

    # Compute and return challenge
    return Bn.from_binary(sha256((jsonpickle.encode(pk) + jsonpickle.encode(randomized_signature) +
                                  jsonpickle.encode(commitment) + message.hex() + jsonpickle.encode(alpha)).encode('utf-8')).digest())
