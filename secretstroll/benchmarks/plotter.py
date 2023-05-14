import matplotlib.pyplot as plt
from typing import Dict
import re


def read_computation_costs_from_file(filename: str) -> Dict[int, float]:
    """ Helper function to read a computation benchmark costs table from a file """

    # Read each line
    with open(filename, "r") as f:
        # Get relevant lines, that contain actual bechmarks
        lines = list(filter(lambda x: "benchmarks" in x, f.readlines()))

        # Split, strip and remove unnecessary information
        lines = [re.split("\s+", line) for line in lines]

        # Strip and convert to actual values
        result = {int(num_attributes.split("[")[-1][:-1]): (float(mean), float(std)) for
                  num_attributes, mean, _, std, _, _ in lines}

    return result


def read_communication_costs_from_file(filename: str) -> Dict[int, float]:
    """ Helper function to read a communication benchmark costs table from a file """

    # Read each line
    with open(filename, "r") as f:
        # Strip lines
        lines = [line.replace(":", "").replace(",", "").split(" ") for line in f.readlines()]

        # Strip and convert to actual values
        result = {int(num_attributes): (float(mean), float(std)) for num_attributes, mean, std in lines}

    return result


def add_to_plot(path: str, filename: str, color: str):
    """ Helper function to plot communication costs for a given filename """

    # Read the communication costs
    costs = read_communication_costs_from_file(path + filename) if "communication" in path \
        else read_computation_costs_from_file(path + filename)

    # Get the mean and std
    mean = {num_attributes: mean for num_attributes, (mean, _) in costs.items()}
    std = {num_attributes: std for num_attributes, (_, std) in costs.items()}

    # Get the label
    label = (filename.split(".")[0] if filename != "key_generation.txt" else "key generation").capitalize()

    # Plot the communication cost
    plt.plot(mean.keys(), mean.values(), label=label, color=color, linestyle='dashed', marker='x', markersize=7)
    plt.errorbar(mean.keys(), mean.values(), yerr=list(std.values()), color=color, linestyle='dashed')


def generate_plot(path: str, show: bool = False):
    """ Helper function to plot communication costs """

    # Set the style
    plt.rc('axes', axisbelow=True)

    # Create the plot
    for filename, color in zip(["key_generation.txt", "issuance.txt", "showing.txt", "verification.txt"],
                               ["blue", "green", "red", "orange"]):
        # No communication costs for verification
        if filename == "verification.txt" and "communication" in path:
            continue

        # Add to plot
        add_to_plot(path, filename, color)

    # Grid background
    plt.grid(which='major', color='#666666', linestyle='-', alpha=0.1)

    # Add legend and labels
    plt.ylabel("Communication cost [bytes]" if "communication" in path else "Computation cost [s]")
    plt.xlabel("Number of attributes")
    plt.legend()

    # Save the plot
    plt.savefig(path + path.replace("/", ".png"), dpi=300)

    # Show the plot
    if show:
        plt.show()


generate_plot("communication_cost_benchmarks/", show=True)
generate_plot("computation_cost_benchmarks/", show=True)
