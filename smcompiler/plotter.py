import matplotlib.pyplot as plt
from collections import OrderedDict

def plot_graph(mean: dict, name:str, std: dict = None):

    for title, points in mean.items():
        x_coord = list(points.keys())
        x_coord.sort()
        mean[title] = {x: points[x] for x in x_coord}

    for experiment, result in mean.items():
        match experiment:
            case "scalar_addition":
                plt.plot(result.keys(), result.values(), label="number of scalar addition")
            case "scalar_multiplication":
                plt.plot(result.keys(), result.values(), label="number of scalar multiplication")
            case "secret_addition":
                plt.plot(result.keys(), result.values(), label="number of secret addition")
            case "secret_multiplication":
                print(result.values())
                plt.plot(result.keys(), result.values(), label="number of secret multiplication")
            case "nb_parties_addition":
                plt.plot(result.keys(), result.values(), label="number of parties in addition")
            case "nb_parties_multiplication":
                plt.plot(result.keys(), result.values(), label="number of parties in multiplication")
        
        if std is not None:
            plt.errorbar(result.keys(), result.values(), list(std[experiment].values()), linestyle='None', marker='o')

        ylabel = name +" cost"
        if "mean" in name or "std" in name:
            ylabel+="(in seconds)"
        else:
            ylabel+="(in bytes)"
        plt.ylabel(ylabel)

    plt.title(name+" cost")
    plt.legend()
    plt.show()

def computation_cost_plot():
    with open("results/computation_cost.txt") as file:
        content = file.readlines()

        experiments_mean_addition = {"scalar_addition": {}, "secret_addition":{}, "nb_parties_addition":{}}
        experiments_std_addition = {"scalar_addition": {}, "secret_addition":{}, "nb_parties_addition":{}}
        experiments_mean_multiplication = {"scalar_multiplication": {}, "secret_multiplication":{}, "nb_parties_multiplication":{}}
        experiments_std_multiplication ={"scalar_multiplication": {}, "secret_multiplication":{}, "nb_parties_multiplication":{}}

        for line in content:
            features = [feature.strip() for feature in line.split()]

            if len(features) > 0 and features[0][0] == 't':
                experiment_parameter = features[0][features[0].index('[')+1:features[0].index(']')].split('-')
                if "scalar_addition" in features[0]:
                    experiments_mean_addition["scalar_addition"][int(experiment_parameter[0])]=float(features[5])
                    experiments_std_addition["scalar_addition"][int(experiment_parameter[0])]=float(features[7])
                elif "scalar_multiplication" in features[0]:
                    experiments_mean_multiplication["scalar_multiplication"][int(experiment_parameter[0])]=float(features[5])
                    experiments_std_multiplication["scalar_multiplication"][int(experiment_parameter[0])]=float(features[7])
                elif "secret_addition" in features[0]:
                    experiments_mean_addition["secret_addition"][int(experiment_parameter[0])]=float(features[5])
                    experiments_std_addition["secret_addition"][int(experiment_parameter[0])]=float(features[7])
                elif "secret_multiplication" in features[0]:
                    experiments_mean_multiplication["secret_multiplication"][int(experiment_parameter[0])]=float(features[5])
                    experiments_std_multiplication["secret_multiplication"][int(experiment_parameter[0])]=float(features[7])
                elif "nb_parties_addition" in features[0]:
                    experiments_mean_addition["nb_parties_addition"][int(experiment_parameter[1])]=float(features[5])
                    experiments_std_addition["nb_parties_addition"][int(experiment_parameter[1])]=float(features[7])
                elif "nb_parties_multiplication" in features[0]:
                    experiments_mean_multiplication["nb_parties_multiplication"][int(experiment_parameter[1])]=float(features[5])
                    experiments_std_multiplication["nb_parties_multiplication"][int(experiment_parameter[1])]=float(features[7])

        plot_graph(experiments_mean_addition, "mean computation addition", experiments_std_addition)
        plot_graph(experiments_mean_multiplication, "mean computation multiplication",  experiments_std_multiplication)

def comm_cost_plotter():
    with open("results/comm_cost.txt") as file:
        content = file.readlines()
        experiments_cost_addition = {"scalar_addition": {}, "secret_addition":{},  "nb_parties_addition":{},}
        experiments_cost_multiplication = { "scalar_multiplication": {},"secret_multiplication":{},  "nb_parties_multiplication":{}} 

        for line in content:
            data = [feature.strip() for feature in line.split(':')]
            experiment_parameter = data[0][data[0].index('[')+1:data[0].index(']')].split('-')

            if "scalar_addition" in data[0]:
                experiments_cost_addition["scalar_addition"][int(experiment_parameter[0])]=int(data[1])
            elif "scalar_multiplication" in data[0]:
                experiments_cost_multiplication["scalar_multiplication"][int(experiment_parameter[0])]=int(data[1])
            elif "secret_addition" in data[0]:
                experiments_cost_addition["secret_addition"][int(experiment_parameter[0])]=int(data[1])
            elif "secret_multiplication" in data[0]:
                experiments_cost_multiplication["secret_multiplication"][int(experiment_parameter[0])]=int(data[1])
            elif "addition_nb_parties" in data[0]:
                experiments_cost_addition["nb_parties_addition"][int(experiment_parameter[1])]=int(data[1])
            elif "multiplication_nb_parties" in data[0]:
                experiments_cost_multiplication["nb_parties_multiplication"][int(experiment_parameter[1])]=int(data[1])

        plot_graph(experiments_cost_addition, "comm addition")
        plot_graph(experiments_cost_addition, "comm multiplication")

computation_cost_plot()
comm_cost_plotter()