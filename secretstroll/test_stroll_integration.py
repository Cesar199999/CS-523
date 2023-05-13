import jsonpickle
from stroll import Client, Server


def test_process_registration_success():

    # Define subscriptions
    subscriptions = ["A", "B", "C", "username"]

    # Generate key pair
    sk, pk = Server.generate_ca(subscriptions)

    # Define server and client
    server, client = Server(), Client()

    # Create some user subscriptions
    user_subscriptions = ["A", "B"]

    # Create an issue request
    serialized_registration, state = client.prepare_registration(
        pk, "user", user_subscriptions)

    # Process the registration
    serialized_credential = server.process_registration(
        sk, pk, serialized_registration, "user", user_subscriptions)

    # Process the response
    credentials = client.process_registration_response(
        pk, serialized_credential, state)

    # Sign a request
    signed_request = client.sign_request(pk, credentials, b"message", ["C"])

    # Verify the signature
    assert server.check_request_signature(
        pk, b"message", ["C"], signed_request)
