import pprint
from datetime import datetime
from typing import List, Dict, Tuple, Union, Any, Set

from data_helpers import Query, QueryLoader, POILoader, JoinHelper
from visualization_helpers import TimeHelper


class PatternHelper:
    """Class to recognize patterns in the anonymized queries."""

    def __init__(self, query_loader: QueryLoader, poi_loader: POILoader):
        self.__query_loader = query_loader
        self.__poi_loader = poi_loader

        # Process the data
        self.__get_queries_by_ip_by_day_by_hour = self.__get_queries_by_ip_by_day_by_hour()

    def print_query_timetable_for_ip(self, ip_address: str):
        """Print the timetable of the queries for the given IP address."""
        pprint.pprint(self.__get_queries_by_ip_by_day_by_hour[ip_address])

    def __get_queries_by_ip_by_day_by_hour(self) -> Dict[str, Dict[int, Dict[int, List[Query]]]]:
        """Process the daily patterns of the users."""

        # Get the IP addresses
        ip_addresses = self.__query_loader.queries_by_ip.keys()

        # Get the queries for each IP address
        return {
            ip_address: {
                i: {
                    j: self.__query_loader.get_queries_for_ip_and_time_range(
                        ip_address,
                        range(j, j + 1),
                        range(i, i + 1)
                    ) for j in range(24)
                } for i in range(7)
            } for ip_address in ip_addresses
        }


class UserProfile:
    """Class to represent a de-anonymized user profile."""

    def __init__(self, ip_address: str):
        self.ip_address = ip_address
        self.home_location, self.home_cell_id = None, None
        self.work_location, self.work_cell_id = None, None
        self.favourite_activity = "unknown"
        self.favourite_activity_times: Set[datetime] = set()

    def __repr__(self):
        # Format the favourite activity times

        return f"User with IP address {self.ip_address} \n" \
               f"   Home location: {self.home_location}, cell id: {self.home_cell_id} \n" \
               f"   Work location: {self.work_location}, cell id: {self.work_cell_id} \n" \
               f"   His/her favourite activity is going to the {self.favourite_activity} \n"

    def plot_favourite_activity_times_timetable(self):
        """Plot the timetable of the favourite activity times."""
        print(f"Timetable of his/her favourite activity: ")
        TimeHelper.plot_datetime_list(list(self.favourite_activity_times))


class AttackHelper:
    """General class for the attack helpers."""

    def __init__(self, query_loader: QueryLoader, poi_loader: POILoader):
        self.__query_loader = query_loader
        self.__poi_loader = poi_loader
        self.__join_helper = JoinHelper(query_loader, poi_loader)

    def get_user_profile_for_ip(self, ip_address: str) -> UserProfile:
        """Return the user profile for the given IP address."""

        # Initialize the user profile
        user_profile = UserProfile(ip_address)

        # Get the queries for the user
        user_profile.work_location, user_profile.work_cell_id = self.__get_work_location(ip_address)

        # Get the home location
        user_profile.home_location, user_profile.home_cell_id = self.__get_home_location(ip_address)

        # Get the most liked activity
        user_profile.favourite_activity = self.__get_most_liked_activity(ip_address)

        # Get the times of the most liked activity
        user_profile.favourite_activity_times = self.__get_most_liked_activity_times(ip_address)

        # Return the profile
        return user_profile

    def __get_work_location(self, ip_address: str) -> Tuple[Tuple[float, float], int]:
        """Return the possible work locations for the given IP address."""

        # Get the queries for the user
        work_queries = self.__query_loader.get_queries_for_ip_and_time_range(ip_address, range(9, 16), range(0, 5))

        # Abort if there are no queries
        if len(work_queries) == 0:
            return None, None

        # Get the frequencies of the locations
        return self.__get_most_frequent_location(work_queries), self.__get_most_frequent_cell_id(work_queries)

    def __get_home_location(self, ip_address: str) -> Tuple[Tuple[float, float], int]:
        """Return the possible home locations for the given IP address."""

        # Get the queries for the user
        home_queries = self.__query_loader.get_queries_for_ip_and_time_range(ip_address, [22, 23, 0, 1, 2, 3, 4, 5],
                                                                             range(0, 4))
        # Abort if there are no queries
        if len(home_queries) == 0:
            return None, None

        # Get the frequencies of the locations
        return self.__get_most_frequent_location(home_queries), self.__get_most_frequent_cell_id(home_queries)

    def __get_most_liked_activity(self, ip_address: str) -> str:
        """Return the most liked hobby for the given IP address."""

        # Get the queries for the user
        hobby_queries = self.__query_loader.get_pois_filter_frequency(ip_address)

        # We are not interested in where he eats or does his groceries
        hobby_queries = {
            poi_type: frequency for poi_type, frequency in hobby_queries.items()
            if poi_type not in ["cafeteria", "restaurant", "supermarket"]
        }

        # Abort if there are no queries
        if len(hobby_queries) == 0:
            return None

        # Get the frequencies of the locations
        return max(hobby_queries, key=hobby_queries.get)

    def __get_most_liked_activity_times(self, ip_address) -> Set[datetime]:
        """Return the query times for the most liked activity for the given IP address."""

        # Get the most liked activity
        most_liked_activity = self.__get_most_liked_activity(ip_address)

        # Abort if there is no most liked activity
        if most_liked_activity is None:
            return set()

        # Get the frequencies of the locations
        return set([
            query.timestamp for query in self.__query_loader.get_queries_for_ip(ip_address)
            if query.poi_type == most_liked_activity
        ])

    @staticmethod
    def __get_location_frequencies(queries: List[Query]) -> dict[tuple[float, float], Union[int, Any]]:
        """Return the frequencies of the locations in the given queries."""
        location_frequencies = {}
        for query in queries:
            location_frequencies[query.location] = location_frequencies.get(query.location, 0) + 1
        return location_frequencies

    @staticmethod
    def __get_most_frequent_location(queries: List[Query]) -> Tuple[float, float]:
        """Return the most frequent location in the given queries."""

        # Get the locations
        locations = list(
            map(
                lambda q: q.location,
                queries
            )
        )

        # Return the most frequent location
        return max(locations, key=locations.count)

    @staticmethod
    def __get_most_frequent_cell_id(queries: List[Query]) -> int:
        """Return the most frequent cell in the given queries."""

        # Get the cell ids
        cell_ids = list(
            map(
                lambda q: q.get_cell_id(),
                queries
            )
        )

        # Return the most frequent cell id
        return max(cell_ids, key=cell_ids.count)
