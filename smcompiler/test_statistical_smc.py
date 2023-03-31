import time
from multiprocessing import Process, Queue

import pytest
import math
import random

from statistical_smc import SecureStatisticsParty
from expression import Scalar, Secret
from protocol import ProtocolSpec
from server import run

from smc_party import SMCParty


def statistical_smc_client(client_id, value_dict, operation, secrets, participants, queue):
    cli = SecureStatisticsParty(
        client_id,
        "localhost",
        5000,
        value_dict,
        secrets,
        participants,
        operation
    )
    res = cli.run()
    queue.put(res)
    print(f"{client_id} has finished!")


def smc_server(args):
    run("localhost", 5000, args)


def run_processes(server_args, *client_args):
    queue = Queue()

    server = Process(target=smc_server, args=(server_args,))
    clients = [Process(target=statistical_smc_client, args=(
        *args, queue)) for args in client_args]

    server.start()
    time.sleep(3)
    for client in clients:
        client.start()

    results = list()
    for client in clients:
        client.join()

    for client in clients:
        results.append(queue.get())

    server.terminate()
    server.join()

    # To "ensure" the workers are dead.
    time.sleep(2)

    print("Server stopped.")

    return results


def suite(parties: dict[str, dict[Secret, int]], operation, expected):
    participants = list(parties.keys())
    secret_dicts = list(parties.values())
    secrets = [
        secret for secret_dict in secret_dicts for secret in secret_dict.keys()]

    clients = [(name, value_dict, operation, secrets, participants)
               for name, value_dict in parties.items()]

    results = run_processes(participants, *clients)
    epsilon = 0.0001

    for result in results:
        assert abs(result - expected) < epsilon


def test_suite1():
    """
    f(a, b, c) = mean(a, b, c)
    """
    alice_secret = Secret()
    bob_secret = Secret()
    charlie_secret = Secret()

    parties = {
        "Alice": {alice_secret: 3},
        "Bob": {bob_secret: 14},
        "Charlie": {charlie_secret: 2}
    }

    expected = (3 + 14 + 2) / 3
    suite(parties, "mean", expected)


def test_suite2():
    """
    f(a, b, c, d, e, f) = mean(a, b, c, d, e, f)
    """
    alice_secret = Secret()
    bob_secret = Secret()
    charlie_secret = Secret()
    dave_secret = Secret()
    eve_secret = Secret()
    frank_secret = Secret()

    parties = {
        "Alice": {alice_secret: 4},
        "Bob": {bob_secret: 6},
        "Charlie": {charlie_secret: 32},
        "Dave": {dave_secret: 5},
        "Eve": {eve_secret: 7},
        "Frank": {frank_secret: 9}
    }

    expected = (4 + 6 + 32 + 5 + 7 + 9) / 6
    suite(parties, "mean", expected)


def test_suite3():
    """
    f(a, b, c) = var(a, b, c)
    """
    alice = Secret()
    bob = Secret()
    charlie = Secret()

    parties = {
        "Alice": {alice: 3},
        "Bob": {bob: 14},
        "Charlie": {charlie: 2}
    }

    average = (3 + 14 + 2) / 3
    expected = 1 / 3 * ((3 - average) ** 2 + (14 - average)
                        ** 2 + (2 - average) ** 2)
    suite(parties, "variance", expected)


def test_suite4():
    """
    f(a, b, c, d, e, f) = var(a, b, c, d, e, f)
    """
    alice = Secret()
    bob = Secret()
    charlie = Secret()
    dave = Secret()
    eve = Secret()
    frank = Secret()

    parties = {
        "Alice": {alice: 4},
        "Bob": {bob: 6},
        "Charlie": {charlie: 32},
        "Dave": {dave: 5},
        "Eve": {eve: 7},
        "Frank": {frank: 9}
    }

    average = (4 + 6 + 32 + 5 + 7 + 9) / 6
    expected = 1 / 6 * ((4 - average) ** 2 + (6 - average) ** 2 + (32 - average)
                        ** 2 + (5 - average) ** 2 + (7 - average) ** 2 + (9 - average) ** 2)
    suite(parties, "variance", expected)


def test_suite5():
    """
    f(a, b, c) = geometric_mean(a, b, c)
    """

    alice = Secret()
    bob = Secret()
    charlie = Secret()

    parties = {
        "Alice": {alice: 3},
        "Bob": {bob: 14},
        "Charlie": {charlie: 2}
    }

    expected = (3 * 14 * 2) ** (1 / 3)
    suite(parties, "geometric_mean", expected)


def test_suite6():
    """
    f(a, b, c, d, e, f) = geometric_mean(a, b, c, d, e, f)
    """

    alice = Secret()
    bob = Secret()
    charlie = Secret()
    dave = Secret()
    eve = Secret()
    frank = Secret()

    parties = {
        "Alice": {alice: 4},
        "Bob": {bob: 6},
        "Charlie": {charlie: 32},
        "Dave": {dave: 5},
        "Eve": {eve: 7},
        "Frank": {frank: 9}
    }

    expected = (4 * 6 * 32 * 5 * 7 * 9) ** (1 / 6)
    suite(parties, "geometric_mean", expected)


def test_suite7():
    """
    f(a, b, c) = exp(a) + exp(b) + exp(c)
    """

    alice = Secret()
    bob = Secret()
    charlie = Secret()

    parties = {
        "Alice": {alice: 2},
        "Bob": {bob: 0},
        "Charlie": {charlie: 1}
    }

    expected = math.exp(2) + math.exp(0) + math.exp(1)
    suite(parties, "sum_of_exponentials", expected)


def test_suite8():
    """
    f(a, b, c, d) = exp(a) + exp(b) + exp(c) + exp(d)
    """

    alice = Secret()
    bob = Secret()
    charlie = Secret()
    dave = Secret()

    parties = {
        "Alice": {alice: 3},
        "Bob": {bob: 1},
        "Charlie": {charlie: 2},
        "Dave": {dave: -1},
    }

    expected = math.exp(3) + math.exp(1) + math.exp(2) + math.exp(-1)
    suite(parties, "sum_of_exponentials", expected)
