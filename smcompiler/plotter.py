import matplotlib.pyplot as plt
from collections import OrderedDict


def plot_graph(mean: dict, name: str, std: dict = None):
    plt.rc('axes', axisbelow=True)

    for title, points in mean.items():
        x_coord = list(points.keys())
        x_coord.sort()
        mean[title] = {x: points[x] for x in x_coord}

    # do not plot lines

    for experiment, result in mean.items():
        match experiment:
            case "scalar_addition":
                plt.plot(result.keys(), result.values(),
                         label="Scalars", marker="x", linestyle="dashed", color="red", markersize=7)
                if std is not None:
                    plt.errorbar(result.keys(), result.values(), list(
                        std[experiment].values()), linestyle='None',  color="red")

            case "scalar_multiplication":
                plt.plot(result.keys(), result.values(),
                         label="Scalars", marker="x", linestyle="dashed", color="green",    markersize=7)
                if std is not None:
                    plt.errorbar(result.keys(), result.values(), list(
                        std[experiment].values()), linestyle='None', color="green")

            case "secret_addition":
                plt.plot(result.keys(), result.values(),
                         label="Secrets", marker="x", linestyle="dashed", color="blue", markersize=7)
                if std is not None:
                    plt.errorbar(result.keys(), result.values(), list(
                        std[experiment].values()), linestyle='None', color="blue")

            case "secret_multiplication":
                plt.plot(result.keys(), result.values(),
                         label="Secrets", marker="x", linestyle="dashed", color="red", markersize=7)

                if std is not None:
                    plt.errorbar(result.keys(), result.values(), list(
                        std[experiment].values()), linestyle='None', color="red")

            case "nb_parties_addition":
                plt.plot(result.keys(), result.values(),
                         label="Addition", marker="x", linestyle="dashed", color="green", markersize=7)

                if std is not None:
                    # add caping to error bars

                    plt.errorbar(result.keys(), result.values(), list(
                        std[experiment].values()), linestyle='None', color="green")
            case "nb_parties_multiplication":
                plt.plot(result.keys(), result.values(),
                         label="Multiplication", marker="x", linestyle="dashed", color="blue", markersize=7)

                if std is not None:
                    plt.errorbar(result.keys(), result.values(), list(
                        std[experiment].values()), linestyle='None', color="blue")

        # add grid lines dashed and dimmed
        plt.grid(which='major', color='#666666', linestyle='-', alpha=0.1)

        plt.ylabel(name)
        if "nb_parties" in experiment:
            plt.xlabel("Number of parties")
        elif "addition" in experiment:
            plt.xlabel("Number of additions")
        elif "multiplication" in experiment:
            plt.xlabel("Number of multiplications")

    # legend box transparent
    # If parties do not show legend
    if "nb_parties" not in experiment:
        plt.legend(loc="upper left", framealpha=0)
    plt.show()


def computation_cost_plot():
    with open("results/computation_cost.txt") as file:
        content = file.readlines()

        experiments_mean_addition = {
            "scalar_addition": {}, "secret_addition": {}}
        experiments_std_addition = {
            "scalar_addition": {}, "secret_addition": {}}
        experiments_mean_multiplication = {"scalar_multiplication": {
        }, "secret_multiplication": {}}
        experiments_std_multiplication = {"scalar_multiplication": {
        }, "secret_multiplication": {}, }

        parties_mean = {"nb_parties_addition": {},
                        "nb_parties_multiplication": {}}
        parties_std = {
            "nb_parties_addition": {},
            "nb_parties_multiplication": {}}

        for line in content:
            features = [feature.strip() for feature in line.split()]

            if len(features) > 0 and features[0][0] == 't':
                experiment_parameter = features[0][features[0].index(
                    '[')+1:features[0].index(']')].split('-')
                if "scalar_addition" in features[0]:
                    experiments_mean_addition["scalar_addition"][int(
                        experiment_parameter[0])] = float(features[5])
                    experiments_std_addition["scalar_addition"][int(
                        experiment_parameter[0])] = float(features[7])
                elif "scalar_multiplication" in features[0]:
                    experiments_mean_multiplication["scalar_multiplication"][int(
                        experiment_parameter[0])] = float(features[5])
                    experiments_std_multiplication["scalar_multiplication"][int(
                        experiment_parameter[0])] = float(features[7])
                elif "secret_addition" in features[0]:
                    experiments_mean_addition["secret_addition"][int(
                        experiment_parameter[0])] = float(features[5])
                    experiments_std_addition["secret_addition"][int(
                        experiment_parameter[0])] = float(features[7])
                elif "secret_multiplication" in features[0]:
                    experiments_mean_multiplication["secret_multiplication"][int(
                        experiment_parameter[0])] = float(features[5])
                    experiments_std_multiplication["secret_multiplication"][int(
                        experiment_parameter[0])] = float(features[7])
                elif "nb_parties_addition" in features[0]:
                    parties_mean["nb_parties_addition"][int(
                        experiment_parameter[1])] = float(features[5])
                    parties_std["nb_parties_addition"][int(
                        experiment_parameter[1])] = float(features[7])
                elif "nb_parties_multiplication" in features[0]:
                    parties_mean["nb_parties_multiplication"][int(
                        experiment_parameter[1])] = float(features[5])
                    parties_std["nb_parties_multiplication"][int(
                        experiment_parameter[1])] = float(features[7])

        plot_graph(experiments_mean_addition,
                   "Time [s]", experiments_std_addition)
        plot_graph(experiments_mean_multiplication,
                   "Time [s]",  experiments_std_multiplication)
        plot_graph(parties_mean,
                   "Time [s]", parties_std)


def comm_cost_plotter():
    with open("results/comm_cost.txt") as file:
        content = file.readlines()
        experiments_cost_addition = {
            "scalar_addition": {}, "secret_addition": {}, }
        experiments_cost_multiplication = {"scalar_multiplication": {
        }, "secret_multiplication": {}}

        parties_mean = {
            "nb_parties_addition": {}, "nb_parties_multiplication": {}}

        for line in content:
            data = [feature.strip() for feature in line.split(':')]
            experiment_parameter = data[0][data[0].index(
                '[')+1:data[0].index(']')].split('-')

            if "scalar_addition" in data[0]:
                experiments_cost_addition["scalar_addition"][int(
                    experiment_parameter[0])] = int(data[1])
            elif "scalar_multiplication" in data[0]:
                experiments_cost_multiplication["scalar_multiplication"][int(
                    experiment_parameter[0])] = int(data[1])
            elif "secret_addition" in data[0]:
                experiments_cost_addition["secret_addition"][int(
                    experiment_parameter[0])] = int(data[1])
            elif "secret_multiplication" in data[0]:
                experiments_cost_multiplication["secret_multiplication"][int(
                    experiment_parameter[0])] = int(data[1])
            elif "addition_nb_parties" in data[0]:
                parties_mean["nb_parties_addition"][int(
                    experiment_parameter[1])] = int(data[1])
            elif "multiplication_nb_parties" in data[0]:
                parties_mean["nb_parties_multiplication"][int(
                    experiment_parameter[1])] = int(data[1])

        plot_graph(experiments_cost_addition, "Communication cost [bytes]")
        plot_graph(experiments_cost_multiplication,
                   "Communication cost [bytes]")
        plot_graph(parties_mean, "Communication cost [bytes]")


computation_cost_plot()
comm_cost_plotter()
