import time
from multiprocessing import Process, Queue

import pytest
import sys

from expression import Expression, Scalar, Secret
from protocol import ProtocolSpec
from server import run
import random
import math

from smc_party import SMCParty


def smc_client(client_id, prot, value_dict, queue):
    cli = SMCParty(
        client_id,
        "localhost",
        5000,
        protocol_spec=prot,
        value_dict=value_dict
    )
    res = cli.run()
    queue.put(res)
    print(f"{client_id} has finished!")


def smc_server(args):
    run("localhost", 5000, args)


def run_processes(expected, server_args, *client_args):
    queue = Queue()

    server = Process(target=smc_server, args=(server_args,))
    clients = [Process(target=smc_client, args=(*args, queue))
               for args in client_args]

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

    for result in results:
        assert result == expected


def suite(parties, expr, expected, benchmark):

    participants = list(parties.keys())
    prot = ProtocolSpec(expr=expr, participant_ids=participants)

    clients = [(name, prot, value_dict)
               for name, value_dict in parties.items()]

    benchmark(run_processes, expected, participants, *clients)


def get_parties(nb_parties=2):
    parties = {}

    for i in range(nb_parties):
        parties[f"party{i}"] = dict()

    return parties


def get_random_values(nb_values: int, bit_length: int) -> list[int]:
    res = []
    for _ in range(nb_values):
        r = random.getrandbits(bit_length)
        while r == 0:
            r = random.getrandbits(bit_length)
        res.append(r)
    return res


def experiment_scalar_additions(nb_scalar_addition=0, nb_parties=2, bit_length=32):

    parties = get_parties(nb_parties)
    values = get_random_values(nb_scalar_addition, bit_length)
    scalars = [Scalar(v) for v in values]

    values += get_random_values(1, bit_length)
    secret = Secret()
    parties[f"party{0}"][secret] = values[-1]

    # We add an extra secret to the list to make sure share exchange happens.
    return parties, secret + sum(scalars[1:], start=scalars[0]), sum(values)


def experiment_scalar_multiplications(nb_scalar_multiplication=0, nb_parties=2, bit_length=32):

    parties = get_parties(nb_parties)
    values = get_random_values(nb_scalar_multiplication, bit_length)
    scalars = [Scalar(v) for v in values]

    values += get_random_values(1, bit_length)
    secret = Secret()
    parties[f"party{0}"][secret] = values[-1]

    # We add an extra secret to the list to make sure share exchange happens.
    return parties, secret * math.prod(scalars[1:], start=scalars[0]), math.prod(values)


def experiment_secret_additions(nb_secret_addition=0, nb_parties=2, bit_length=32):

    parties = get_parties(nb_parties)
    values = get_random_values(nb_secret_addition, bit_length)
    secrets = [Secret() for _ in values]

    for secret, value in zip(secrets, values):
        party = f"party{int(random.random()  * nb_parties)}"
        parties[party][secret] = value

    return parties, sum(secrets[1:], start=secrets[0]), sum(values)


def experiment_secret_multiplications(nb_secret_multiplication=0, nb_parties=2, bit_length=32):

    parties = get_parties(nb_parties)
    values = get_random_values(nb_secret_multiplication, bit_length)
    secrets = [Secret() for _ in values]

    for secret, value in zip(secrets, values):
        party = f"party{int(random.random()  * nb_parties)}"
        parties[party][secret] = value

    return parties, math.prod(secrets[1:], start=secrets[0]), math.prod(values)


def experiment_definition(nb_parties=2, bit_length=8, nb_scalar_addition=0, nb_scalar_multiplication=0, nb_secret_addition=0, nb_secret_multiplication=0):
    sys.setrecursionlimit(20000)

    # Init random seed
    random.seed(time.time())

    if nb_scalar_addition > 0:
        return experiment_scalar_additions(
            nb_scalar_addition=nb_scalar_addition, nb_parties=nb_parties, bit_length=bit_length)

    elif nb_scalar_multiplication > 1:
        return experiment_scalar_multiplications(
            nb_scalar_multiplication=nb_scalar_multiplication, nb_parties=nb_parties, bit_length=bit_length)

    elif nb_secret_addition > 0:
        return experiment_secret_additions(
            nb_secret_addition=nb_secret_addition, nb_parties=nb_parties, bit_length=bit_length)

    elif nb_secret_multiplication > 1:
        return experiment_secret_multiplications(
            nb_secret_multiplication=nb_secret_multiplication, nb_parties=nb_parties, bit_length=bit_length)

    else:
        raise ValueError("No experiment defined")


### Run with python3 -m pytest benchmark.py -k 'test_scalar_addition' --benchmark-autosave --benchmark-sort=mean ###

@pytest.mark.parametrize("nb_scalar_addition, nb_parties", [
    (2, 4), (50, 4), (100, 4), (500, 4), (1000, 4)
])
def test_scalar_addition(nb_scalar_addition, nb_parties, benchmark):
    parties, expr, expected = experiment_definition(bit_length=16,
                                                    nb_scalar_addition=nb_scalar_addition, nb_parties=nb_parties)
    suite(parties, expr, expected, benchmark)


### Run with python3 -m pytest benchmark.py -k 'test_scalar_multiplication' --benchmark-autosave --benchmark-sort=mean ###

@ pytest.mark.parametrize("nb_scalar_multiplication, nb_parties", [
    (2, 4), (10, 4), (20, 4), (40, 4), (80, 4),
])
def test_scalar_multiplication(nb_scalar_multiplication, nb_parties, benchmark):
    parties, expr, expected = experiment_definition(
        nb_scalar_multiplication=nb_scalar_multiplication, nb_parties=nb_parties)
    suite(parties, expr, expected, benchmark)


### Run with python3 -m pytest benchmark.py -k 'test_secret_addition' --benchmark-autosave --benchmark-sort=mean ###

@ pytest.mark.parametrize("nb_secret_addition, nb_parties", [
    (2, 4), (50, 4), (100, 4), (500, 4), (1000, 4)
])
def test_secret_addition(nb_secret_addition, nb_parties, benchmark):
    parties, expr, expected = experiment_definition(bit_length=16,
                                                    nb_secret_addition=nb_secret_addition, nb_parties=nb_parties)
    suite(parties, expr, expected, benchmark)


### Run with python3 -m pytest benchmark.py -k 'test_secret_multiplication' --benchmark-autosave --benchmark-sort=mean ###

@ pytest.mark.parametrize("nb_secret_multiplication, nb_parties", [
    # max bit length of (nb_secret_multiplication * bit_length) before overflow modulo p is 1024
    (2, 4), (10, 4), (20, 4), (40, 4), (80, 4)
])
def test_secret_multiplication(nb_secret_multiplication, nb_parties, benchmark):
    parties, expr, expected = experiment_definition(
        nb_secret_multiplication=nb_secret_multiplication, nb_parties=nb_parties)
    suite(parties, expr, expected, benchmark)

@ pytest.mark.parametrize("nb_secret_multiplication, nb_parties", [
    # max bit length of (nb_secret_multiplication * bit_length) before overflow modulo p is 1024
    (2, 2), (2, 4), (2, 8), (2, 16), (2, 32), (2, 64)
])
def test_nb_parties_multiplication(nb_secret_multiplication, nb_parties, benchmark):
    parties, expr, expected = experiment_definition(
        nb_secret_multiplication=nb_secret_multiplication, nb_parties=nb_parties)
    suite(parties, expr, expected, benchmark)

@ pytest.mark.parametrize("nb_secret_addition, nb_parties", [
    (2, 2), (2, 4), (2, 8), (2, 16), (2, 32), (2, 64)
])
def test_nb_parties_addition(nb_secret_addition, nb_parties, benchmark):
    parties, expr, expected = experiment_definition(bit_length=16,
                                                    nb_secret_addition=nb_secret_addition, nb_parties=nb_parties)
    suite(parties, expr, expected, benchmark)
