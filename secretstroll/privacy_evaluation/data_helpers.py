from collections import Counter
from datetime import datetime, timedelta
from typing import List, Tuple

import numpy as np

from query import get_nearby_pois


def project(location: Tuple[float, float]) -> Tuple[int, float, float]:
    # Project the location to the grid
    cell_x = ((location[0] - 46.5) / 0.07) * 10
    cell_y = ((location[1] - 6.55) / 0.1) * 10
    cell_id = int(cell_x) * 10 + int(cell_y)

    return cell_id, cell_x, cell_y


class Query:
    """Class to represent a user query."""

    def __init__(self, ip_address: str, location: tuple[float, float], timestamp: float, poi_type: str):
        self.ip_address = ip_address
        self.location = location
        self.timestamp = datetime(2023, 5, 22, 0, 0, 0) + timedelta(hours=timestamp)
        self.poi_type = poi_type

    def __repr__(self):
        return f"Query(ip={self.ip_address}, location={self.location}, " \
               f"timestamp={self.timestamp}, filter={self.poi_type})"

    def __eq__(self, other):
        return self.ip_address == other.ip_address and self.location == other.location \
            and self.timestamp == other.timestamp and self.poi_type == other.poi_type

    def __hash__(self):
        return hash((self.ip_address, self.location, self.timestamp, self.poi_type))

    def get_cell_location(self) -> Tuple[float, float]:
        """Return the location of the cell."""
        return project(self.location)[1:]

    def get_cell_id(self) -> int:
        """Return the ID of the cell."""
        return project(self.location)[0]


class QueryLoader:

    def __init__(self, filename: str = "queries.csv"):
        self.queries = self.__load(filename)
        self.queries_by_ip = self.__group_by_ip(self.queries)

    def __repr__(self):
        return f"QueryLoader(queries={self.queries})"

    def get_queries_for_ip(self, ip_address: str) -> List[Query]:
        """Return a list of queries for the specified IP address."""
        return self.queries_by_ip[ip_address]

    def get_locations_for_ip(self, ip_address: str) -> List[tuple[float, float]]:
        """Return a list of locations for the specified IP address."""
        return [query.location for query in self.get_queries_for_ip(ip_address)]

    def get_cell_locations_for_ip(self, ip_address: str) -> List[tuple[float, float]]:
        """Return a list of locations for the specified IP address."""
        return [query.get_cell_location() for query in self.get_queries_for_ip(ip_address)]

    def get_queries_for_ip_and_time_range(self, ip_address: str, retain_hours: range = None,
                                          retain_weekdays: range = None) -> List[Query]:
        """Return a list of queries for the specified IP address and time range."""
        # Initialize the list of queries
        filtered_queries = self.get_queries_for_ip(ip_address)

        # Filter the queries by the specified hours and weekdays
        if retain_hours is not None:
            filtered_queries = [query for query in filtered_queries if query.timestamp.hour in retain_hours]

        if retain_weekdays is not None:
            filtered_queries = [query for query in filtered_queries if query.timestamp.weekday() in retain_weekdays]

        return filtered_queries

    def get_pois_filter_frequency(self, ip_address: str) -> dict[str, int]:
        """Return a dictionary of POI types and their frequencies for the specified IP address."""

        # Get the queries for the specified IP address
        queries = self.get_queries_for_ip(ip_address)

        # Get the POI types and their frequencies
        return {
            query.poi_type: sum(1 for q in queries if q.poi_type == query.poi_type)
            for query in queries
        }

    @staticmethod
    def __load(filename: str) -> List[Query]:
        """Load the queries.csv file and return a list of Query objects."""
        with open(filename, "r") as f:
            # Skip the header and split the entries
            entries = f.readlines()[1:]

            return [QueryLoader.__query_from_entry(entry.split(" ")) for entry in entries]

    @staticmethod
    def __group_by_ip(queries: List[Query]) -> dict[str, List[Query]]:
        """Group the queries by IP address."""
        queries_by_ip = {}

        # Group the queries by IP address
        for query in queries:
            queries_by_ip.setdefault(query.ip_address, []).append(query)

        return queries_by_ip

    @staticmethod
    def __query_from_entry(entry: List[str]) -> Query:
        """Parse a line of the queries.csv file and return a Query object."""
        return Query(ip_address=entry[0], location=(float(entry[1]), float(entry[2])),
                     timestamp=float(entry[3]), poi_type=entry[4][:-1])  # Remove the newline


class POI:
    """Class to represent a Point of Interest (POI)."""

    def __init__(self, poi_id: int, cell_id: int, poi_type: str, location: tuple[float, float]):
        self.poi_id = poi_id
        self.cell_id = cell_id
        self.poi_type = poi_type
        self.location = location

    def __repr__(self):
        return f"POI(id={self.poi_id}, cell={self.cell_id}, type={self.poi_type}, location={self.location})"

    def __eq__(self, other):
        return self.poi_id == other.poi_id

    def __hash__(self):
        return hash(self.poi_id)

    def get_cell_location(self) -> Tuple[float, float]:
        """Return the location of the cell."""
        return project(self.location)[1:]

    def get_cell_id(self) -> int:
        """Return the ID of the cell."""
        return project(self.location)[0]


class POILoader:
    """Class to load POI data from the pois.csv file."""

    def __init__(self, filename: str = "pois.csv"):
        self.pois = self.__load(filename)
        self.pois_by_cell_id = self.__group_by_cell(self.pois)
        self.pois_by_id = self.__group_by_id(self.pois)

    def __repr__(self):
        return f"POILoader(pois={self.pois})"

    def get_pois_for_cell(self, cell_id: int) -> List[POI]:
        """Return a list of POIs for the specified cell ID."""
        return self.pois_by_cell_id[cell_id]

    def get_poi_for_id(self, poi_id: int) -> POI:
        """Return a POI object for the specified POI ID."""
        return self.pois_by_id[poi_id]

    @staticmethod
    def __load(filename: str) -> List[POI]:
        """Load the pois.csv file and return a list of POI objects."""

        with open(filename, "r") as f:
            # Skip the header and split the entries
            entries = f.readlines()[1:]

            # Create a POI object for each entry
            return [POILoader.__poi_from_entry(entry.split(" ")) for entry in entries]

    @staticmethod
    def __group_by_cell(pois: List[POI]) -> dict[int, List[POI]]:
        """Group the POIs by cell ID."""

        pois_by_cell = {}

        # Group the POIs by cell ID
        for poi in pois:
            pois_by_cell.setdefault(poi.cell_id, []).append(poi)

        return pois_by_cell

    @staticmethod
    def __group_by_id(pois: List[POI]) -> dict[int, POI]:
        """Group the POIs by POI ID."""
        return {poi.poi_id: poi for poi in pois}

    @staticmethod
    def __poi_from_entry(entry: List[str]) -> POI:
        """Parse a line of the pois.csv file and return a POI object."""
        return POI(poi_id=int(entry[0]), cell_id=int(entry[1]),
                   poi_type=entry[2], location=(float(entry[3]), float(entry[4])))


class JoinHelper:
    """Class to represent a join between queries and POIs."""

    def __init__(self, query_loader: QueryLoader, poi_loader: POILoader):
        self.__query_loader = query_loader
        self.__poi_loader = poi_loader

    def get_nearby_pois_frequencies_for_ip(self, ip_address: str, retain_hours: range = None,
                                           retain_weekdays: range = None) -> dict[POI, int]:
        """Return a dictionary of cell IDs and their frequencies for the specified IP address."""

        # Get the queries for the specified IP address
        queries_by_ip = self.__query_loader.get_queries_for_ip_and_time_range(ip_address, retain_hours, retain_weekdays)

        # Get the ids of the nearby POIs for each query
        nearby_pois_ids = list(
            map(lambda query: get_nearby_pois(np.array(query.location), query.poi_type), queries_by_ip)
        )

        # Get the frequencies of the nearby POIs, flatten and count
        nearby_pois_ids_freq = Counter([item for sublist in nearby_pois_ids for item in sublist])

        # Return the actual POIs and their frequencies
        return {
            self.__poi_loader.get_poi_for_id(poi_id): freq
            for poi_id, freq in nearby_pois_ids_freq.items()
        }
