from credential import *

user_state = UserState()


def test_signature_consistency_success():
    """ Test that a signature is consistent with the public key """
    # Generate key pair
    sk, pk = generate_key(["A", "B", "C"])

    # Sign a message
    signature = sign(sk, [b"1", b"2", b"3"])

    # Check that signature is consistent with public key
    assert verify(pk, signature, [b"1", b"2", b"3"])


def test_signature_consistency_failure():
    """ Test that a signature is not consistent with the public key """
    # Generate key pair
    sk, pk = generate_key(["A", "B", "C"])

    # Sign a message
    signature = sign(sk, [b"1", b"2", b"3"])

    # Check that signature is not consistent with public key
    assert not verify(pk, signature, [b"1", b"2", b"4"])


def test_create_issue_request_success_1():
    """ Test that issue request generation works and is valid """

    # Generate key pair
    _, pk = generate_key(range(10))

    # Create some user attributes
    user_attributes = {0: b"A", 1: b"B", 2: b"C"}

    # Create an issue request
    issue_request = create_issue_request(pk, user_attributes, user_state)

    # Check that the issue request is valid
    assert verify_issue_request(issue_request, pk)


def test_create_issue_request_success_2():
    """ Test that issue request generation works and is valid """

    # Generate key pair
    _, pk = generate_key(range(10))

    # Create some user attributes
    user_attributes = {1: b"A", 2: b"B", 6: b"F"}

    # Create an issue request
    issue_request = create_issue_request(pk, user_attributes, user_state)

    # Check that the issue request is valid
    assert verify_issue_request(issue_request, pk)


def test_create_issue_request_success_3():
    """ Test that issue request generation works and is valid """

    # Generate key pair
    _, pk = generate_key(range(10))

    # Create some user attributes, shuffled
    user_attributes = {1: b"A", 6: b"F", 2: b"B"}

    # Create an issue request
    issue_request = create_issue_request(pk, user_attributes, user_state)

    # Check that the issue request is valid
    assert verify_issue_request(issue_request, pk)


def test_create_issue_request_failure_on_pk_modification():
    """ Test that an issue request is not valid on incorrect attributes """
    # Generate key pair
    _, pk = generate_key(range(10))

    # Create some user attributes
    user_attributes = {0: b"A", 1: b"B", 2: b"C"}

    # Create an issue request
    issue_request = create_issue_request(pk, user_attributes, user_state)

    # Modify the public key
    pk[1][0] = G1.neutral_element()

    # Check that the issue request is not valid
    assert not verify_issue_request(issue_request, pk)


def test_create_sign_unblind_signature_success():
    """ Test that an issue request can be signed and unblinded """
    # Generate key pair
    sk, pk = generate_key(range(6))

    # Create some user attributes
    user_attributes = {0: b"A", 1: b"B", 2: b"C"}

    # Get issuer attributes
    issuer_attributes = {i: i.to_bytes(1, "big")
                         for i in set(range(6)) - user_attributes.keys()}

    # Create an issue request
    issue_request = create_issue_request(pk, user_attributes, user_state)

    # Sign the issue request
    signed_issue_request = sign_issue_request(
        sk, pk, issue_request, issuer_attributes)

    # Obtain the credential
    credential_signature, credentials = obtain_credential(
        pk, signed_issue_request, user_state)

    sorted_credentials = [credentials[i]
                          for i in sorted(credentials.keys())]

    # Check that the credential is valid
    assert verify(pk, credential_signature, sorted_credentials)


def test_create_sign_unblind_signature_failure_on_credential_modification():
    """ Test that a signed issue request is not valid on credential modification """
    # Generate key pair
    sk, pk = generate_key(range(6))

    # Create some user attributes
    user_attributes = {0: b"A", 1: b"B", 2: b"C"}

    # Get issuer attributes
    issuer_attributes = {i: i.to_bytes(1, "big")
                         for i in set(range(6)) - user_attributes.keys()}

    # Create an issue request
    issue_request = create_issue_request(pk, user_attributes, user_state)

    # Sign the issue request
    signed_issue_request = sign_issue_request(
        sk, pk, issue_request, issuer_attributes)

    # Obtain the credential
    credential_signature, credentials = obtain_credential(
        pk, signed_issue_request, user_state)

    sorted_credentials = [credentials[i]
                          for i in sorted(credentials.keys())]

    # Modify the credential
    sorted_credentials[0] = b"error"

    # Check that the credential is not valid
    assert not verify(pk, credential_signature, sorted_credentials)


def test_create_sign_unblind_signature_failure_on_credential_signature_modification():
    """ Test that a signed issue request is not valid on credential modification """
    # Generate key pair
    sk, pk = generate_key(range(6))

    # Create some user attributes
    user_attributes = {0: b"A", 1: b"B", 2: b"C"}

    # Get issuer attributes
    issuer_attributes = {i: i.to_bytes(1, "big")
                         for i in set(range(6)) - user_attributes.keys()}

    # Create an issue request
    issue_request = create_issue_request(pk, user_attributes, user_state)

    # Sign the issue request
    signed_issue_request = sign_issue_request(
        sk, pk, issue_request, issuer_attributes)

    # Obtain the credential
    credential_signature, credentials = obtain_credential(
        pk, signed_issue_request, user_state)

    sorted_credentials = [credentials[i]
                          for i in sorted(credentials.keys())]

    # Modify the credential signature
    malicous_credential_signature = G1.neutral_element(
    ), credential_signature[1]

    # Check that the credential is not valid
    assert not verify(pk, malicous_credential_signature, sorted_credentials)


def test_showing_protocol_success_1():
    # Generate key pair
    sk, pk = generate_key(range(6))

    # Create some user attributes
    user_attributes = {0: b"A", 1: b"B", 2: b"C"}

    # Get issuer attributes
    issuer_attributes = {i: i.to_bytes(1, "big")
                         for i in set(range(6)) - user_attributes.keys()}

    # Create an issue request
    issue_request = create_issue_request(pk, user_attributes, user_state)

    # Sign the issue request
    signed_issue_request = sign_issue_request(
        sk, pk, issue_request, issuer_attributes)

    # Obtain the credential
    credential = obtain_credential(
        pk, signed_issue_request, user_state)

    # Create a disclosure proof
    proof = create_disclosure_proof(
        pk, credential, [b"A"], b"test")

    # Check that the proof is valid
    assert verify_disclosure_proof(pk, proof, b"test")


def test_showing_protocol_success_2():
    # Generate key pair
    sk, pk = generate_key(range(6))

    # Create some user attributes, shuffle them
    user_attributes = {0: b"A", 4: b"B", 3: b"C"}

    # Get issuer attributes
    issuer_attributes = {i: i.to_bytes(1, "big")
                         for i in set(range(6)) - user_attributes.keys()}

    # Create an issue request
    issue_request = create_issue_request(pk, user_attributes, user_state)

    # Sign the issue request
    signed_issue_request = sign_issue_request(
        sk, pk, issue_request, issuer_attributes)

    # Obtain the credential
    credential = obtain_credential(
        pk, signed_issue_request, user_state)

    # Create a disclosure proof
    proof = create_disclosure_proof(
        pk, credential, [b"A"], b"test")

    # Check that the proof is valid
    assert verify_disclosure_proof(pk, proof, b"test")


def test_showing_protocol_failure_on_credential_modification():
    # Generate key pair
    sk, pk = generate_key(range(6))

    # Create some user attributes
    user_attributes = {0: b"A", 1: b"B", 2: b"C"}

    # Get issuer attributes
    issuer_attributes = {i: i.to_bytes(1, "big")
                         for i in set(range(6)) - user_attributes.keys()}

    # Create an issue request
    issue_request = create_issue_request(pk, user_attributes, user_state)

    # Sign the issue request
    signed_issue_request = sign_issue_request(
        sk, pk, issue_request, issuer_attributes)

    # Obtain the credential
    credential_signature, _ = obtain_credential(
        pk, signed_issue_request, user_state)

    # Modify the credentials
    credentials = {0: b"error", 1: b"error", 2: b"error",
                   3: b"error", 4: b"error", 5: b"error"}

    # Create a disclosure proof
    proof = create_disclosure_proof(
        pk, (credential_signature, credentials), [b"error"], b"test")

    # Check that the proof is not valid
    assert not verify_disclosure_proof(pk, proof, b"test")


def test_showing_protocol_failure_on_credential_left_signature_modification():
    # Generate key pair
    sk, pk = generate_key(range(6))

    # Create some user attributes
    user_attributes = {0: b"A", 1: b"B", 2: b"C"}

    # Get issuer attributes
    issuer_attributes = {i: i.to_bytes(1, "big")
                         for i in set(range(6)) - user_attributes.keys()}

    # Create an issue request
    issue_request = create_issue_request(pk, user_attributes, user_state)

    # Sign the issue request
    signed_issue_request = sign_issue_request(
        sk, pk, issue_request, issuer_attributes)

    # Obtain the credential
    credential_signature, credentials = obtain_credential(
        pk, signed_issue_request, user_state)

    # Modify the credential signature
    malicous_credential_signature = G1.neutral_element(
    ), credential_signature[1]

    # Create a disclosure proof
    proof = create_disclosure_proof(
        pk, (malicous_credential_signature, credentials), [b"A"], b"test")

    # Check that the proof is not valid
    assert not verify_disclosure_proof(pk, proof, b"test")


def test_showing_protocol_failure_on_credential_right_signature_modification():
    # Generate key pair
    sk, pk = generate_key(range(6))

    # Create some user attributes
    user_attributes = {0: b"A", 1: b"B", 2: b"C"}

    # Get issuer attributes
    issuer_attributes = {i: i.to_bytes(1, "big")
                         for i in set(range(6)) - user_attributes.keys()}

    # Create an issue request
    issue_request = create_issue_request(pk, user_attributes, user_state)

    # Sign the issue request
    signed_issue_request = sign_issue_request(
        sk, pk, issue_request, issuer_attributes)

    # Obtain the credential
    credential_signature, credentials = obtain_credential(
        pk, signed_issue_request, user_state)

    # Modify the credential signature
    malicous_credential_signature = credential_signature[0], G1.neutral_element(
    )

    # Create a disclosure proof
    proof = create_disclosure_proof(
        pk, (malicous_credential_signature, credentials), [b"A"], b"test")

    # Check that the proof is not valid
    assert not verify_disclosure_proof(pk, proof, b"test")
