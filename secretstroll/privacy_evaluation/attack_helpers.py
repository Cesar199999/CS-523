import random
from datetime import datetime
from multiprocessing import Pool
from typing import List, Dict, Tuple, Union, Any, Set

import numpy as np
import seaborn as sns
from matplotlib import pyplot as plt
from tqdm import tqdm

from data_helpers import Query, QueryLoader, POILoader


class UserProfile:
    """Class to represent a de-anonymized user profile."""

    def __init__(self, ip_address: str):
        self.ip_address = ip_address
        self.home_location, self.home_cell_id, self.home_discriminator, self.total_work_queries = None, -1, 0, 0
        self.work_location, self.work_cell_id, self.work_discriminator, self.total_home_queries = None, -1, 0, 0
        self.favourite_activity = "unknown"
        self.favourite_activity_times: Set[datetime] = set()

    def __repr__(self):
        # Format the favourite activity times

        return f"User with IP address {self.ip_address} \n" \
               f"   Home location: {self.home_location}, cell id: {self.home_cell_id} " \
               f"({self.home_discriminator * 100}% of the ({self.total_home_queries}) queries sent between 18:00 - 20:59 during weekdays come from this location) \n" \
               f"   Work location: {self.work_location}, cell id: {self.work_cell_id} " \
               f"({self.work_discriminator * 100}% of the ({self.total_work_queries}) queries sent between 9:00 - 15:59 during weekdays come from this location) \n" \
               f"   His/her favourite activity is going to the {self.favourite_activity} \n"

    def __hash__(self):
        return hash(self.ip_address)

    def __eq__(self, other):
        return self.ip_address == other.ip_address

    def plot_favourite_activity_times_timetable(self):
        """Plot the timetable of the favourite activity times."""
        print(f"Timetable of his/her favourite activity: ")
        TimeHelper.plot_datetime_list(list(self.favourite_activity_times))


class AttackHelper:
    """General class for the attack helpers."""

    def __init__(self, query_loader: QueryLoader, poi_loader: POILoader):
        self.__query_loader = query_loader
        self.__poi_loader = poi_loader
        self.user_profiles: Dict[str, UserProfile] = {}

    def get_user_profiles(self) -> Dict[str, UserProfile]:
        """Return the user profiles for all the users."""

        print("Getting user profiles...")

        # Parallelize the computation of the user profiles
        with Pool() as pool:
            user_profiles = pool.map(
                self.get_user_profile_for_ip,
                tqdm(self.__query_loader.queries_by_ip.keys())
            )

        # Return the user profiles as a dictionary
        return {user_profile.ip_address: user_profile for user_profile in user_profiles}

    def get_user_profile_for_ip(self, ip_address: str) -> UserProfile:
        """Return the user profile for the given IP address."""

        # Check if the user profile already exists
        if ip_address in self.user_profiles:
            return self.user_profiles[ip_address]

        # Initialize the user profile
        user_profile = UserProfile(ip_address)

        # Get the queries for the user
        user_profile.work_location, user_profile.work_cell_id, user_profile.work_discriminator, user_profile.total_work_queries = self \
            .__get_work_location(ip_address)

        # Get the home location
        user_profile.home_location, user_profile.home_cell_id, user_profile.home_discriminator, user_profile.total_home_queries = self \
            .__get_home_location(ip_address)

        # Get the most liked activity
        user_profile.favourite_activity = self.__get_most_liked_activity(ip_address)

        # Get the times of the most liked activity
        user_profile.favourite_activity_times = self.__get_most_liked_activity_times(ip_address)

        # Update the user profiles dictionary and return the user profile
        return self.user_profiles.setdefault(ip_address, user_profile)

    def __get_work_location(self, ip_address: str) -> Tuple[Tuple[float, float], int, float, int]:
        """Return the possible work locations for the given IP address."""

        # Get the queries for the user
        return self.__get_profile_from_queries(
            self.__query_loader.get_queries_for_ip_and_time_range(ip_address, range(9, 16), range(0, 5)))

    def __get_home_location(self, ip_address: str) -> Tuple[Tuple[float, float], int, float, int]:
        """Return the possible home locations for the given IP address."""

        # Get the queries for the user
        # If queries are sent consistently during the late night, the user is probably at home, so we don't check those
        # hours
        return self.__get_profile_from_queries(
            self.__query_loader.get_queries_for_ip_and_time_range(ip_address, range(18, 20), [0, 1, 2, 3, 6]))

    def __get_profile_from_queries(self, queries: List[Query]) -> Tuple[Tuple[float, float], int, float, int]:
        """Return the location profile for the given IP address."""

        # Abort if there are no queries
        if len(queries) == 0:
            return (-1, -1), -1, 0, 0

        # Get the frequencies of the locations
        location_frequencies = self.__get_location_frequencies(queries)

        # Get the most frequent location
        most_frequent_location = max(location_frequencies, key=location_frequencies.get)

        # Get the percentage of queries done from this location
        queries_discriminator = location_frequencies[most_frequent_location] / len(queries)

        # Get the frequencies of the locations
        return most_frequent_location, self.__get_most_frequent_cell_id(queries), queries_discriminator, len(queries)

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
    def __get_most_frequent_cell_id(queries: List[Query]) -> int:
        """Return the most frequent cell in the given queries."""

        # Get the cell ids
        cell_ids = list(
            map(
                lambda q: q.get_cell_id(),
                queries
            )
        )
        random.shuffle(cell_ids)

        # Return the most frequent cell id, choose at random if there are multiple
        return max(cell_ids, key=cell_ids.count)


class TimeHelper:

    @staticmethod
    def plot_datetime_list(datetime_list: List[datetime]) -> None:
        """Plot the datetime list. Each integer on the x-axis represents a day.
            Each integer on the y-axis represents an hour. """

        # Init the np array
        heat_grid = np.zeros((24, 7))

        # Iterate over the datetime list
        for dt in datetime_list:
            # Get the day and hour
            day = dt.weekday()
            hour = dt.hour

            # Add the value to the array
            heat_grid[hour, day] += 1

        # Plot the data as sns heatmap
        sns.heatmap(heat_grid, cmap="Greys", fmt="d", alpha=1, zorder=2, vmin=0,
                    yticklabels=[str(i) if i % 3 == 0 else "" for i in range(24)],
                    xticklabels=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"])

        # show the heatmap
        plt.show()
