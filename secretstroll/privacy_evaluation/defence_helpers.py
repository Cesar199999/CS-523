import functools
import hashlib
import operator
import time
from functools import reduce
from random import uniform, sample
from typing import List, Dict, Tuple

import numpy as np
from IPython.core.display_functions import clear_output
from matplotlib import pyplot as plt
from petrelic.bn import Bn

from data_helpers import Query, POILoader, QueryLoader
from secretstroll.privacy_evaluation.attack_helpers import AttackHelper, UserProfile


class HashedQuery(Query):

    def __init__(self, query: Query, client_hash_key: Bn):
        super().__init__(query.ip_address, query.location, 0.0, query.poi_type)
        self.timestamp = query.timestamp
        self.__hash = self.__hash_query(client_hash_key)

    def __hash_query(self, client_hash_key: Bn) -> str:
        """Hash the query using the client's hash key."""
        return hashlib.sha256(
            f"{self.ip_address}{self.location}{self.timestamp}{self.poi_type}{client_hash_key}".encode()
        ).hexdigest()

    def __repr__(self):
        return f"Query[hash={self.__hash}](ip={self.ip_address}, location={self.location}, timestamp={self.timestamp}, poi_type={self.poi_type})"


class QueryObfuscator:

    def __init__(self, client_hash_key: Bn):
        self.client_hash_key = client_hash_key
        self.randomized_locations = {}
        self.randomized_transformations = [
            lambda x, y: (x, y),
        ]

    def obfuscate_queries_smoothly(self, queries: List[Query], k: int) -> List[HashedQuery]:
        """Obfuscate the queries by generating k smooth queries for each query."""
        pass

    def obfuscate_queries_consistently(self, queries: List[Query], k: int) -> List[HashedQuery]:
        """Obfuscate the queries by generating k consistent queries for each query."""

        # Obfuscate the queries by location
        return reduce(
            lambda x, y: x + y, [
                [self.__hash_query(
                    self.__get_query_with_changed_location(query, randomized_location)
                ) for randomized_location in self.randomized_locations.setdefault(
                    query.location, [
                                        self.__random_location() for _ in range(k)
                                    ] + [query.location])
                ] for query in queries
            ]
        )

    def obfuscate_queries_random(self, queries: List[Query], k: int) -> List[HashedQuery]:
        """Obfuscate the queries by generating k random queries for each query."""

        # Generate k random queries and flatten the list
        return reduce(lambda x, y: x + y, [
            self.__obfuscate_query_random(query, k) for query in queries
        ])

    def __obfuscate_query_random(self, query: Query, k: int) -> List[HashedQuery]:
        """Obfuscate the query by generating k random queries."""

        # Generate k random queries
        obfuscated_queries = [self.__randomize_query(query) for _ in range(k)] + [query]

        # Hash the queries
        return [self.__hash_query(obfuscated_query) for obfuscated_query in obfuscated_queries]

    def __hash_query(self, query: Query) -> HashedQuery:
        """Obfuscate the query using the client's hash key."""
        return HashedQuery(query, self.client_hash_key)

    @staticmethod
    def __group_by_location(queries: List[Query]) -> Dict[Tuple[float, float], List[Query]]:
        """Group the queries by location."""

        # Group the queries by location
        queries_by_location = {}
        for query in queries:
            queries_by_location.setdefault(query.location, []).append(query)

        return queries_by_location

    @staticmethod
    def __get_query_with_changed_location(query: Query, location: Tuple[float, float]) -> Query:
        """Return a query with a changed location."""
        new_query = Query(query.ip_address, location, 0.0, query.poi_type)
        new_query.timestamp = query.timestamp
        return new_query

    @staticmethod
    def __randomize_query(query: Query) -> Query:
        """Randomize the query location."""

        # Uniformly sample a random location
        location = QueryObfuscator.__random_location()

        # Return a randomized query
        return QueryObfuscator.__get_query_with_changed_location(query, location)

    @staticmethod
    def __random_location() -> Tuple[float, float]:
        """Uniformly sample a random location"""
        return uniform(46.5, 46.57), uniform(6.55, 6.65)


class Experiments:

    def __init__(self, queries: List[Query], poi_loader: POILoader):
        self.original_queries = queries
        self.poi_loader = poi_loader

    def attack_times(self) -> None:
        """Plot the attack times."""
        n_users_list = [1, 10, 20, 40, 60, 80, 100, 150, 200]
        initial_loader = QueryLoader(queries=self.original_queries)

        times = {
            n_users: [self.__measure_attack_time(QueryLoader(
                # Flatten the list
                queries=functools.reduce(
                    operator.iconcat,
                    # Sample n_users random users
                    [initial_loader.queries_by_ip[ip] for ip in
                     sample(initial_loader.queries_by_ip.keys(), n_users)],
                    [])
                # To compute the std
            )) for _ in range(10)]
            for n_users in n_users_list
        }

        # Plot the attack times
        self.__plot_attack_times(times)

    def location_learning_difficulty(self, k: int = 1) -> None:
        """Compute the location learning difficulty."""

        # Create the query obfuscator
        query_obfuscator = QueryObfuscator(Bn(100).random())

        # Obfuscate the queries
        query_loader = QueryLoader(
            queries=query_obfuscator.obfuscate_queries_consistently(self.original_queries, k)
            if k > 1 else self.original_queries
        )

        # Create the attacker and get the user profiles
        user_profiles = AttackHelper(query_loader, self.poi_loader).get_user_profiles()

        # Compute the location learning difficulty
        location_learning_difficulty = self.__get_discriminator_stats(user_profiles)

        # Plot the location learning difficulty
        self.__plot_discriminator_stats(*location_learning_difficulty)

    def cell_id_learning_difficulty(self, n: int = 5) -> None:
        """Compute the cell id learning difficulty."""

        # Create the query obfuscator
        original_user_profiles = AttackHelper(QueryLoader(queries=self.original_queries),
                                              self.poi_loader).get_user_profiles()
        clear_output(wait=False)

        # Initialize the measures
        mean_work, std_work = [], []
        mean_home, std_home = [], []

        # Compute the cell id learning difficulty
        for k in range(1, 10):
            measures_work, measures_home = self.__get_cell_id_learning_difficulty(original_user_profiles, k, n)
            mean_work.append(np.mean(measures_work))
            std_work.append(np.std(measures_work))
            mean_home.append(np.mean(measures_home))
            std_home.append(np.std(measures_home))

        # Plot the cell id learning difficulty
        self.__plot_cell_id_learning_difficulty(mean_work, std_work, mean_home, std_home)

    def __get_cell_id_learning_difficulty(self, original_user_profiles: Dict[str, UserProfile], k: int, n: int) -> \
            Tuple[List[float], List[float]]:
        """Compute the cell id learning difficulty."""

        measures_work, measures_home = [], []
        for _ in range(n):
            # Create the query obfuscator
            query_obfuscator = QueryObfuscator(Bn(100).random())

            # Obfuscate the queries
            query_loader = QueryLoader(
                queries=query_obfuscator.obfuscate_queries_consistently(self.original_queries, k)
            )

            # Create the attacker and get the user profiles
            user_profiles = AttackHelper(query_loader, self.poi_loader).get_user_profiles()
            clear_output(wait=False)

            # Compute the cell id learning difficulty
            work_cell_id_learning_difficulty = sum([
                1 if original_user_profiles[ip].work_cell_id == user_profiles[ip].work_cell_id else 0 for ip in
                original_user_profiles.keys()
            ]) / len(original_user_profiles.keys())

            home_cell_id_learning_difficulty = sum([
                1 if original_user_profiles[ip].home_cell_id == user_profiles[ip].home_cell_id else 0 for ip in
                original_user_profiles.keys()
            ]) / len(original_user_profiles.keys())

            measures_work.append(work_cell_id_learning_difficulty)
            measures_home.append(home_cell_id_learning_difficulty)

        return measures_work, measures_home

    def __get_discriminator_stats(self, user_profiles: Dict[str, UserProfile]) -> Tuple[List[float], List[float]]:
        """Plot the work discriminator stats."""

        # Get the work discriminator values
        work_discriminator_stats = [user_profile.work_discriminator for user_profile in user_profiles.values() if
                                    user_profile.work_discriminator is not None]

        # Get the home discriminator values
        home_discriminator_stats = [user_profile.home_discriminator for user_profile in user_profiles.values() if
                                    user_profile.home_discriminator is not None]

        return work_discriminator_stats, home_discriminator_stats

    def __plot_discriminator_stats(self, work_discriminator_stats: List[float],
                                   home_discriminator_stats: List[float]) -> None:
        # Clear the plot
        plt.clf()
        # Plot the histograms
        plt.hist(work_discriminator_stats, bins=100, alpha=0.5, label="work")
        plt.hist(home_discriminator_stats, bins=100, alpha=0.5, label="home")
        plt.xlabel("Discriminator value (relevant queries / total queries)")
        plt.ylabel("Frequency")
        plt.legend(loc='upper right')
        plt.show()

    def __measure_attack_time(self, query_loader: QueryLoader) -> float:
        """Measure the attack time for a query loader."""

        # Start the timer
        start_time = time.time()

        # Create the attacker
        AttackHelper(query_loader, self.poi_loader).get_user_profiles()
        clear_output(wait=False)

        # Stop the timer
        end_time = time.time()

        # Return the attack time
        return end_time - start_time

    def __plot_attack_times(self, times: Dict[int, List[float]]) -> None:
        # Clear the plot
        plt.clf()

        # Set the style
        plt.rc('axes', axisbelow=True)

        # Get mean and std
        mean = {n_users: np.mean(times[n_users]) for n_users in times}
        std = {n_users: np.std(times[n_users]) for n_users in times}

        # Plot the mean
        plt.errorbar(mean.keys(), mean.values(), yerr=list(std.values()), color='black', linestyle='dashed',
                     linewidth=0.6,
                     marker='x', markersize=3, capsize=3, label="Attack time")
        # Grid background
        plt.grid(which='major', color='#666666', linestyle='-', alpha=0.1)

        # Add legend and labels
        plt.ylabel("Attack time (s)")
        plt.xlabel("Number of de-anonymized users")
        plt.legend(frameon=False, numpoints=1)

    def __plot_cell_id_learning_difficulty(self, mean_work, std_work, mean_home, std_home) -> None:
        # Clear the plot
        plt.clf()

        # Set the style
        plt.rc('axes', axisbelow=True)

        # Plot the values
        plt.errorbar(range(1, len(mean_work) + 1), mean_work, yerr=list(std_work), color='red', linestyle='dashed',
                     linewidth=0.6,
                     marker='x', markersize=3, capsize=3, label="Work cell ID")
        plt.errorbar(range(1, len(mean_work) + 1), mean_home, yerr=list(std_home), color='blue', linestyle='dashed',
                     linewidth=0.6,
                     marker='x', markersize=3, capsize=3, label="Home cell ID")

        # Grid background
        plt.grid(which='major', color='#666666', linestyle='-', alpha=0.1)

        # Add legend and labels
        plt.ylabel("Cell ID learning difficulty")
        plt.xlabel("Number of obfuscated queries")
        plt.legend(frameon=False, numpoints=1)
