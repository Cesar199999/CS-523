import hashlib
from functools import reduce
from random import uniform
from typing import List, Dict, Tuple, Callable

from petrelic.bn import Bn

from data_helpers import Query
from visualization_helpers import LocationHelper


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
