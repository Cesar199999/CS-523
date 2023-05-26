import datetime
from typing import List, Dict, Tuple, Union

import matplotlib.image as mpimg
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from matplotlib.lines import Line2D

from data_helpers import Query, POI


class LocationHelper:
    """Class to represent locations in the grid."""
    grid_bounds = (46.5, 46.57, 6.55, 6.65)

    def __init__(self, grid_size: int = 10, background_file: str = "map.png"):
        self.grid_size = grid_size
        self.pois: Dict[POI, int] = {}
        self.queries_by_cell_location: Dict[Tuple[float, float], List[Query]] = {}
        self.poi_types: List[str] = []
        self.colors = ["red", "blue", "green", "yellow", "orange", "purple", "pink", "brown", "gray", "olive", "cyan"]
        self.color_map = {}
        self.background_file = background_file

    def clean(self) -> None:
        """Clean the grid."""
        self.pois = {}
        self.queries_by_cell_location = {}
        self.poi_types = []
        self.color_map = {}

    def add_queries_to_grid(self, queries: List[Query]) -> None:
        """Add the locations to the grid."""
        for queries in queries:
            self.__add_query_to_grid(queries)

    def add_pois_to_grid(self, pois: Union[Dict[POI, int], List[POI]]) -> None:
        """Add the POIs to the grid."""
        if isinstance(pois, list):
            for poi in pois:
                self.__add_poi_to_grid(poi)
        else:
            for poi, frequency in pois.items():
                self.__add_poi_to_grid(poi, frequency)

    def show_cell_heatmap(self, show_nearby_pois: bool = False, show_query_locations: bool = False) -> None:
        """Show the heatmap of the cells."""

        # Extract the data
        cell_ids_freq = {i: 0 for i in range(self.grid_size ** 2)}

        if show_nearby_pois:
            for poi, freq in self.pois.items():
                cell_ids_freq[poi.cell_id - 1] += freq

        if show_query_locations:
            for location, queries in self.queries_by_cell_location.items():
                # Get the cell id
                cell_id = queries[0].get_cell_id()

                # Filter the queries by the specified hours and weekdays
                cell_ids_freq[cell_id] += len(queries)

        # Plot the heatmap
        heat_grid = np.array(list(cell_ids_freq.values())).reshape(self.grid_size, self.grid_size)
        h = sns.heatmap(heat_grid, cmap="coolwarm", fmt="d", alpha=0.7, zorder=2)
        h.imshow(mpimg.imread(self.background_file), aspect=h.get_aspect(), extent=h.get_xlim() + h.get_ylim(),
                 zorder=1)

    def show_grid(self, show_nearby_pois=True, show_locations=True) -> None:
        """Show the grid."""

        # Create the figure
        plt.figure(figsize=(10, 10))
        ax = plt.axes(projection="3d")

        # Show always 10 x 10 grid
        ax.set_xlim3d(0, self.grid_size)
        ax.set_ylim3d(0, self.grid_size)

        markers = []

        # Show the nearby POIs
        if show_nearby_pois:
            markers += self.__show_pois(ax)

        # Show the locations
        if show_locations:
            markers += self.__show_locations(ax)

        # Initialize the view
        ax.view_init(15, 30)

        # Show the legend
        plt.legend(markers, self.poi_types + ["user location"], numpoints=1)
        plt.show()

    def __add_poi_to_grid(self, poi: POI, frequency: int = 1) -> None:
        """Add a location to the grid."""
        # Add the POI to the list of POIs
        self.pois[poi] = self.pois.get(poi, 0) + frequency

        # Add the POI type to the list of POI types
        if poi.poi_type not in self.poi_types:
            self.poi_types.append(poi.poi_type)
            self.color_map[poi.poi_type] = self.colors[(len(self.poi_types) - 1) % len(self.colors)]

    def __add_query_to_grid(self, query: Query) -> None:
        """Add a query to the grid."""

        # Add the query to the list of queries
        self.queries_by_cell_location[query.get_cell_location()] = self.queries_by_cell_location \
                                                                       .get(query.get_cell_location(), []) + [query]

    def __show_pois(self, ax: plt.axes) -> list[Line2D]:
        """ Add POIs to the plot."""

        # Color of the point depends on the POI type
        for poi, frequency in self.pois.items():
            # Add the POI type to the list of POI types
            cell_x, cell_y = poi.get_cell_location()

            # Add the POI to the list of POIs
            ax.scatter3D(cell_x, cell_y, frequency, color=self.color_map[poi.poi_type], marker='o', s=2)
            ax.plot([cell_x, cell_x], [cell_y, cell_y], [0, frequency], color=self.color_map[poi.poi_type],
                    linestyle=':', linewidth=0.5)

        # For the legend
        return [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in
                self.color_map.values()]

    def __show_locations(self, ax: plt.axes) -> list[Line2D]:
        """ Add locations to the plot."""

        # Iterate over the locations
        for location, queries in self.queries_by_cell_location.items():
            # Add the Location to the list of Locations
            cell_x, cell_y = location

            # Add the POI to the list of POIs
            ax.scatter3D(cell_x, cell_y, len(queries), color='black', marker='x')
            ax.plot([cell_x, cell_x], [cell_y, cell_y], [0, len(queries)], color='black', linestyle='dashed',
                    linewidth=1)

        # For the legend
        return [plt.Line2D([0, 0], [0, 0], color='black', marker='o', linestyle='')]


class TimeHelper:
    @staticmethod
    def plot_datetime_list(datetime_list: List[datetime.datetime]) -> None:
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
        h = sns.heatmap(heat_grid, cmap="Greys", fmt="d", alpha=1, zorder=2, vmin=0,
                        yticklabels=[str(i) if i % 3 == 0 else "" for i in range(24)],
                        xticklabels=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"])

        # show the heatmap
        plt.show()
