#!/usr/bin/env python
"""Main module responsible for the attack graph generation pipeline."""

import sys
import os
import time

from graphviz import Digraph
from components import reader
from components import writer
from components import topology_parser as top_par
from components import vulnerability_parser as vul_par
from components import attack_graph_parser as att_gr_par

def visualize_attack_graph(example_folder_path, nodes, edges):
    """This function visualizes the attack graph with given counter examples."""

    dot = Digraph(comment="Attack Graph")
    for node in nodes:
        dot.node(node)
    for edge in edges:
        dot.edge(edges[edge][0], edges[edge][1], contstraint='false')

    writer.write_attack_graph(example_folder_path, dot)
    print("Vizualizing the graph...")

def main(example_folder, goal_container):
    """Main function responsible for running the attack graph generation pipeline."""

    # Opening the configuration file.
    config = reader.read_config_file()

    # Create folder where the result files will be stored.
    writer.create_folder(os.path.basename(example_folder))

    # Parsing the topology of the docker containers.
    time_start = time.time()
    top_par.parse_topology(example_folder)
    print("Time elapsed: "+str(time.time() - time_start)+" seconds.\n")

    # Parsing the vulnerabilities for each docker container.
    time_start = time.time()
    vul_par.parse_vulnerabilities(example_folder)
    print("Time elapsed: "+str(time.time() - time_start)+" seconds.\n")

    # Getting the attack graph nodes and edges from the attack paths.
    time_start = time.time()
    nodes, edges = att_gr_par.generate_attack_graph(goal_container,
                                                    example_folder,
                                                    config["attack-vector-folder-path"],
                                                    config["attack-vector-filter"])
    print("Time elapsed: "+str(time.time() - time_start)+" seconds.\n")

    # Visualizing the attack graph.
    time_start = time.time()
    visualize_attack_graph(example_folder, nodes, edges)
    print("Time elapsed: "+str(time.time() - time_start)+" seconds.\n")

if __name__ == "__main__":

    # Checks if the command-line input and config file content is valid.
    IS_VALID_INPUT = reader.validate_command_line_input(sys.argv)
    IS_VALID_CONFIG = reader.validate_config_file()

    if not IS_VALID_CONFIG:
        print("The config file is not valid.")
        exit()

    if IS_VALID_INPUT:

        # Checks if the docker-compose file is valid.
        IS_VALID_COMPOSE = top_par.validation_docker_compose(sys.argv[1])
        if IS_VALID_COMPOSE:
            main(sys.argv[1], sys.argv[2])
    else:
        print("Please have a look at the --help.")
