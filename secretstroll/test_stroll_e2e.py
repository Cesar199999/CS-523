import argparse
from contextlib import redirect_stdout
from io import StringIO

import jsonpickle
import pytest
from petrelic.multiplicative.pairing import G1

import client as client
import random

from credential import AnonymousCredential

# Tests the system end-to-end, from the client's perspective


################### SERVER MUST BE RUNNING FOR THESE TESTS TO PASS ####################

# SERVER_COMMANDS:
# Run the following commands in the docker server container to set up the server:
# python3 server.py setup -S restaurant -S bar -S hotel -S park -S museum -S theatre -S cinema -S gym -S pool -S spa
# python3 server.py run

# CLIENT_COMMANDS:
# Run the following commands in the docker client container to test the protocol:
# pytest test_stroll_e2e.py
# or, if you want to run also the integration and unit tests execute:
# pytest

################### SERVER MUST BE RUNNING FOR THESE TESTS TO PASS ####################

# Define subscriptions
subscription_list = ["restaurant", "bar", "hotel", "park", "museum", "theatre", "cinema", "gym", "pool", "spa"]

# To test shuffling of subscriptions:
# TODO: Server returns any POI, skeleton's fault: https://moodle.epfl.ch/mod/forum/discuss.php?d=89847
client_subscriptions = random.sample(subscription_list, random.randint(1, len(subscription_list)))


def test_successful_registration_and_retrieval():
    # Setup client
    get_pk()

    # Register client
    register()

    # Get location request
    raw_observed_pois = get_loc_request_output()

    if "You are near" not in raw_observed_pois:
        raise Exception("Client did not receive any POIs")

    # remove the "You are near" part
    observed_pois = raw_observed_pois.replace("You are near ", "").replace("\"", "").split(".\n")[:-1]

    # Check the expected POIs are received
    assert set(observed_pois) == {'Harris-Smith', 'Wright, Mitchell and Fitzgerald', 'Madden-Mejia', 'Ramos PLC',
                                  'Miller, Nixon and Terrell', 'Cruz Group', 'Lane-Good', 'Brown, Williams and Reed'}


def test_unsuccessful_registration_wrong_signature():
    # Setup client
    get_pk()

    # Register client
    register()

    # Get credential
    credential: AnonymousCredential = get_credential()

    # Unpack credential
    signature, attributeMap = credential

    # Modify signature
    signature = (G1.hash_to_point(b"wrong signature"), signature[1])

    # Write credential to file
    write_credential((signature, attributeMap))

    # Check the expected error message is received
    with pytest.raises(client.ClientHTTPError) as _:
        get_loc_request_output()


def test_unsuccessful_registration_wrong_attribute_map():
    # Setup client
    get_pk()

    # Register client
    register()

    # Get credential
    credential: AnonymousCredential = get_credential()

    # Unpack credential
    signature, attributeMap = credential

    # Modify map
    attributeMap[random.randint(0, len(attributeMap) - 1)] = b"wrong attribute"

    # Write credential to file
    write_credential((signature, attributeMap))

    # Check the expected error message is received
    with pytest.raises(client.ClientHTTPError) as _:
        get_loc_request_output()


def get_pk(pub_str="key-client.pub", tor=False):
    client.client_get_pk(
        args=argparse.Namespace(
            out=open(pub_str, "wb"),
            tor=tor
        )
    )


def register(pub_str="key-client.pub", out="anon.cred", user=str(random.randint(0, 1000000)), subscriptions=None,
             tor=False):
    if subscriptions is None:
        subscriptions = client_subscriptions

    client.client_register(
        args=argparse.Namespace(
            pub=open(pub_str, "rb"),
            out=open(out, "wb"),
            user=user,
            subscriptions=subscriptions,
            tor=tor
        )
    )


def get_loc_request_output(pub_str="key-client.pub", credential_str="anon.cred", lat=46.52345, lon=6.57890,
                           types=None, tor=False):
    if types is None:
        types = client_subscriptions

    f = StringIO()
    with redirect_stdout(f):
        client.client_loc(
            args=argparse.Namespace(
                pub=open(pub_str, "rb"),
                credential=open(credential_str, "rb"),
                lat=lat,
                lon=lon,
                types=types,
                tor=tor,
            )
        )

    return f.getvalue()


def write_credential(credential: AnonymousCredential, credential_str="anon.cred"):
    with open(credential_str, "wb") as f:
        # Serialize the credential
        f.write(bytes(jsonpickle.encode(credential, keys=True), 'utf-8'))


def get_credential(credential_str="anon.cred") -> AnonymousCredential:
    credential: AnonymousCredential
    with open(credential_str, "rb") as f:
        # Deserialize the credential
        credential = jsonpickle.decode(f.read().decode('utf-8'), keys=True)

    return credential
