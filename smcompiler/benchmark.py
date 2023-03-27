"""
Integration tests that verify different aspects of the protocol.
You can *add* new tests here, but it is best to  add them to a new test file.

ALL EXISTING TESTS IN THIS SUITE SHOULD PASS WITHOUT ANY MODIFICATION TO THEM.
"""

import time
from multiprocessing import Process, Queue

import pytest

from expression import Scalar, Secret
from protocol import ProtocolSpec
from server import run
from random import random

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


def run_processes(server_args, *client_args):
    queue = Queue()

    server = Process(target=smc_server, args=(server_args,))
    clients = [Process(target=smc_client, args=(*args, queue)) for args in client_args]

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


def suite(parties, expr):
    participants = list(parties.keys())
    prot = ProtocolSpec(expr=expr, participant_ids=participants)
    clients = [(name, prot, value_dict) for name, value_dict in parties.items()]
    results = run_processes(participants, *clients)
    return results

def experiment_definition(nb_scalar_addition=0, nb_secret_addition=0, nb_scalar_multiplication=0, nb_secret_multiplication=0, nb_parties=2):
    
    #generate 2 secrets by default
    secrets = [Secret() for _ in range(2)]

    parties = {'Party_{}'.format(i+1): {secrets[i]:i} if i < 2 else {} for i in range(nb_parties)}

    expr = Scalar(0)

    if nb_scalar_addition > 0:
        for i in range(nb_scalar_addition):
            expr+= Scalar(i+1)
    
    if nb_scalar_multiplication > 0:
        expr = Scalar(1)    
        for i in range(nb_scalar_multiplication):
           expr *= Scalar(1 if random() < 0.99 else 2)

    if nb_secret_addition > 0 or nb_secret_multiplication > 0:
        expr = secrets[0]
        for i in range(nb_secret_addition):
            expr += Secret()

        for i in range(nb_secret_multiplication):
            expr *= Secret()

    return(parties, expr)

def test_scalar_addition_10(benchmark):
    parties, expr = experiment_definition(nb_scalar_addition=10)
    benchmark(suite,parties, expr)

def test_scalar_addition_100(benchmark):
    parties, expr = experiment_definition(nb_scalar_addition=100)
    benchmark(suite,parties, expr)

def test_scalar_addition_500(benchmark):
    parties, expr = experiment_definition(nb_scalar_addition=500)
    benchmark(suite,parties, expr)

def test_scalar_addition_1000(benchmark):
    parties, expr = experiment_definition(nb_scalar_addition=1000)
    benchmark(suite,parties, expr)

def test_scalar_multiplication_10(benchmark):
    parties, expr = experiment_definition(nb_scalar_multiplication=10)
    benchmark(suite,parties, expr)

def test_scalar_multiplication_100(benchmark):
    parties, expr = experiment_definition(nb_scalar_multiplication=100)
    benchmark(suite,parties, expr)

def test_scalar_multiplication_500(benchmark):
    parties, expr = experiment_definition(nb_scalar_multiplication=500)
    benchmark(suite,parties, expr)

def test_scalar_multiplication_1000(benchmark):
    parties, expr = experiment_definition(nb_scalar_multiplication=1000)
    benchmark(suite,parties, expr)

def test_ecretr_addition_10(benchmark):
    parties, expr = experiment_definition(nb_secret_addition=10)
    benchmark(suite, parties, expr)

def test_secret_addition_100(benchmark):
    parties, expr = experiment_definition(nb_secretaddition=100)
    benchmark(suite, parties, expr)

def test_secret_addition_500(benchmark):
    parties, expr = experiment_definition(nb_secretaddition=500)
    benchmark(suite, parties, expr)

def test_secret_addition_1000(benchmark):
    parties, expr = experiment_definition(nb_secretaddition=1000)
    benchmark(suite, parties, expr)

def test_secret_multiplication_10(benchmark):
    parties, expr = experiment_definition(nb_secretmultiplication=10)
    benchmark(suite, parties, expr)

def test_secret_multiplication_100(benchmark):
    parties, expr = experiment_definition(nb_secretmultiplication=100)
    benchmark(suite, parties, expr)

def test_secret_multiplication_500(benchmark):
    parties, expr = experiment_definition(nb_secretmultiplication=500)
    benchmark(suite, parties, expr)

def test_secret_multiplication_1000(benchmark):
    parties, expr = experiment_definition(nb_secretmultiplication=1000)
    benchmark(suite, parties, expr)

def test_parties_4(benchmark):
    parties, expr = experiment_definition(nb_parties=4, nb_scalar_addition=1)
    benchmark(suite, parties, expr)

def test_parties_8(benchmark):
    parties, expr = experiment_definition(nb_parties=8, nb_scalar_addition=1)
    benchmark(suite, parties, expr)

def test_parties_16(benchmark):
    parties, expr = experiment_definition(nb_parties=16, nb_scalar_addition=1)
    benchmark(suite, parties, expr)

def test_parties_32(benchmark):
    parties, expr = experiment_definition(nb_parties=32, nb_scalar_addition=1)
    benchmark(suite, parties, expr)

def test_parties_64(benchmark):
    parties, expr = experiment_definition(nb_parties=64, nb_scalar_addition=1)
    benchmark(suite, parties, expr)