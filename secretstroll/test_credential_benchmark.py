import pytest

from stroll import *

key_bytes, issuance_bytes, showing_bytes = {}, {}, {}
num_attributes_parameter = [1, 5, 10, 20, 50, 100]

############################ BENCKMARK COMMANDS ##############################
# pytest test_credential_benchmark.py -k test_key_generation_benchmarks --benchmark-columns=mean,stddev
# pytest test_credential_benchmark.py -k test_issuance_benchmarks --benchmark-columns=mean,stddev
# pytest test_credential_benchmark.py -k test_showing_benchmarks --benchmark-columns=mean,stddev
# pytest test_credential_benchmark.py -k test_verification_benchmarks --benchmark-columns=mean,stddev
##############################################################################

@pytest.mark.parametrize("num_attributes", num_attributes_parameter)
def test_key_generation_benchmarks(num_attributes: int, benchmark):
    """ Test the communication and time complexity of the key generation protocol """

    # Arguments to the key generation protocol
    args = (num_attributes,)

    # Benchmark the key generation
    benchmark.pedantic(key_generation, args, iterations=10, rounds=10)


@pytest.mark.parametrize("num_attributes", num_attributes_parameter)
def test_issuance_benchmarks(num_attributes: int, benchmark):
    """ Test the communication and time complexity of the key generation protocol """

    # Generate a key pair and subscriptions
    args = key_generation(num_attributes)

    # Benchmark the issuance protocol
    benchmark.pedantic(issuance_protocol, args, iterations=10, rounds=10)


@pytest.mark.parametrize("num_attributes", num_attributes_parameter)
def test_showing_benchmarks(num_attributes: int, benchmark):
    """ Test the communication and time complexity of the key generation protocol """

    # Generate a key pair and subscriptions
    args = key_generation(num_attributes)

    # Issue a credential
    args = issuance_protocol(*args)

    # Benchmark the showing protocol
    benchmark.pedantic(showing_protocol, args, iterations=10, rounds=10)


@pytest.mark.parametrize("num_attributes", num_attributes_parameter)
def test_verification_benchmarks(num_attributes: int, benchmark):
    """ Test the communication and time complexity of the key generation protocol """

    # Generate a key pair and subscriptions
    args = key_generation(num_attributes)

    # Issue a credential
    args = issuance_protocol(*args)

    # Show the credential
    args = showing_protocol(*args)

    # Benchmark the verification protocol
    benchmark.pedantic(verification_protocol, args, iterations=10, rounds=10)


def key_generation(num_attributes: int):
    """ Helper function to benchmark the key generation protocol """

    # Create subscriptions
    subscriptions, user_subscriptions = generate_subscriptions(num_attributes)

    # Generate a key pair
    sk, pk = Server.generate_ca(subscriptions)

    # Get output bytes
    append_to_communication_benchmark_queue(num_attributes, len(sk) + len(pk), key_bytes)

    return Server(), Client(), sk, pk, subscriptions, user_subscriptions, num_attributes


def issuance_protocol(server, client, sk, pk, subscriptions, user_subscriptions, num_attributes: int):
    """ Helper function to benchmark the issuance protocol """

    # Create an issue request
    serialized_registration, state = client.prepare_registration(pk, "user", user_subscriptions)

    # Process the registration
    serialized_response = server.process_registration(sk, pk, serialized_registration, "user", user_subscriptions)

    # Process the response
    credentials = client.process_registration_response(pk, serialized_response, state)

    # Get output bytes
    append_to_communication_benchmark_queue(num_attributes, len(serialized_registration) + len(serialized_response),
                                            issuance_bytes)

    return server, client, sk, pk, subscriptions, user_subscriptions, credentials, num_attributes


def showing_protocol(server, client, sk, pk, subscriptions, user_subscriptions, credentials, num_attributes: int):
    # Sign a request
    signed_request = client.sign_request(pk, credentials, b"message", user_subscriptions)

    # Get output bytes
    append_to_communication_benchmark_queue(num_attributes, len(signed_request), showing_bytes)

    return server, client, sk, pk, subscriptions, user_subscriptions, credentials, signed_request, num_attributes


def verification_protocol(server, client, sk, pk, subscriptions, user_subscriptions, credentials, signed_request,
                          num_attributes: int):
    # Verify the signature
    assert server.check_request_signature(pk, b"message", user_subscriptions, signed_request)


@pytest.fixture(scope="session", autouse=True)
def write_communication_cost():
    """ Trick to write to a file after all tests have run """
    yield None

    # Write the communication cost to a file
    write_communication_benchmark_queue(key_bytes, "benchmarks/communication_cost_benchmarks/key_generation.txt")
    write_communication_benchmark_queue(issuance_bytes, "benchmarks/communication_cost_benchmarks/issuance.txt")
    write_communication_benchmark_queue(showing_bytes, "benchmarks/communication_cost_benchmarks/showing.txt")


def generate_subscriptions(num_subscriptions: int) -> Tuple[List[str], List[str]]:
    """ Helper function to generate subscriptions """

    # Create subscriptions
    subscriptions = list(map(str, range(num_subscriptions)))
    user_subscriptions = subscriptions[:num_subscriptions // 2] + ["username"]
    subscriptions += ["username"]

    return subscriptions, user_subscriptions


def append_to_communication_benchmark_queue(num_attributes: int, n_bytes: int, queue: Dict[int, List[int]]):
    """ Helper function to append to a communication benchmark queue """

    # Append to the queue
    if num_attributes not in queue:
        queue[num_attributes] = []
    queue[num_attributes].append(n_bytes)


def write_communication_benchmark_queue(queue: Dict[int, List[int]], filename: str):
    """ Helper function to write a communication benchmark queue to a file """

    mean = lambda x: sum(x) / len(x)
    std = lambda x: sum((y - mean(x)) ** 2 for y in x) / len(x)

    # Write the communication cost of key generation
    with open(filename, "w") as f:
        for n_attributes, n_bytes in queue.items():
            f.write(f"{n_attributes}: {mean(n_bytes)}, {std(n_bytes)}\n")


def test_foo(write_communication_cost):
    pass
