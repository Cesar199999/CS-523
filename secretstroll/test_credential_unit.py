import pytest

from credential import *


# =========================== PS Signature Tests ===========================
def test_generate_key_success():
    """ Tests that the key generation protocol succeeds """
    # Generate a key pair
    sk, pk = generate_key(list(range(10)))

    # Check that the key pair is valid
    assert is_valid_key_pair(sk, pk)


def test_generate_key_failure():
    """ Tests that the key generation protocol fails """

    # Generate a key pair
    sk, pk = generate_key(list(range(10)))

    # Mutate the key pair
    sk = (sk[0] + 1, sk[1], sk[2])

    # Check that the key pair is invalid
    assert not is_valid_key_pair(sk, pk)


def test_sign_success():
    """ Tests signing a message """

    # Generate a key pair
    sk, pk = generate_key(list(range(3)))

    # Check that the key pair is valid
    sign(sk, [b"A", b"B", b"C"])


def test_sign_failure():
    """ Tests signing a message with an invalid key pair """

    # Generate a key pair
    sk, pk = generate_key(list(range(3)))

    # Check that the key pair is valid
    with pytest.raises(AssertionError):
        sign(sk, [b"A", b"B", b"C", b"D"])


def test_verify_success():
    """ Tests verifying a signature """

    # Generate a key pair
    sk, pk = generate_key(list(range(3)))

    # Check the signature is valid
    signature = sign(sk, [b"A", b"B", b"C"])

    # Check that the signature is valid
    assert verify(pk, signature, [b"A", b"B", b"C"])


def test_verify_failure():
    """ Tests verifying an invalid signature """

    # Generate a key pair
    sk, pk = generate_key(list(range(3)))

    # Check the signature is valid
    signature = sign(sk, [b"A", b"B", b"C"])

    # Check that the signature is valid
    assert not verify(pk, signature, [b"A", b"B", b"error"])


# ============================ HELPERS ============================

def is_valid_key_pair(sk, pk):
    """ Asserts that the key pair is valid """

    # Unpack the key pair
    (x, X, y), (g, Y, g_tilde, X_tilde, Y_tilde) = sk, pk

    # Check that the public key is valid
    return (g ** x == X) and ([g ** i for i in y] == Y) and \
        (g_tilde ** x == X_tilde) and ([g_tilde ** i for i in y] == Y_tilde)
