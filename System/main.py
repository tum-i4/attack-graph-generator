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

def visualize_attack_graph(labels_edges,
                           example_folder_path,
                           nodes,
                           edges):
    """This function visualizes the attack graph with given counter examples."""

    dot = Digraph(comment="Attack Graph")
    for node in nodes:
        dot.node(node)

    for edge_name in edges.keys():
        terminal_points = edge_name.split("|")

        edge_vuls = edges[edge_name]

        if labels_edges == "single":
            for edge_vul in edge_vuls:
                dot.edge(terminal_points[0],
                         terminal_points[1],
                         label=edge_vul,
                         contstraint='false')

        elif labels_edges == "multiple":
            desc = ""
            for edge_vul in edge_vuls:
                if desc == "":
                    desc += edge_vul
                else:
                    desc += "\n"+edge_vul
            dot.edge(terminal_points[0],
                     terminal_points[1],
                     label=desc, contstraint='false')

    writer.write_attack_graph(example_folder_path, dot)
    print("Vizualizing the graph...")


def main(example_folder):
    """Main function responsible for running the attack graph generation pipeline."""

    # Opening the configuration file.
    config = reader.read_config_file()

    # Create folder where the result files will be stored.
    writer.create_folder(os.path.basename(example_folder))

    # Parsing the topology of the docker containers.
    time_start = time.time()
    topology, duration_topology = top_par.parse_topology(example_folder)
    duration_topology = time.time() - time_start
    print("Time elapsed: "+str(duration_topology)+" seconds.\n")

    # Visualizing the topology graph.
    duration_visualization = 0
    if config['generate_graphs']:
        time_start = time.time()
        top_par.create_topology_graph(topology,
                                      example_folder)
        duration_visualization = time.time() - time_start
        print("Time elapsed: "+str(duration_visualization)+" seconds.\n")

    # Parsing the vulnerabilities for each docker container.
    vulnerabilities = {}
    duration_vulnerabilities = 0
    if config["mode"] == "online":
        time_start = time.time()
        vul_par.parse_vulnerabilities(example_folder)
        duration_vulnerabilities = time.time() - time_start
        print("Time elapsed: "+str(duration_vulnerabilities)+" seconds.\n")

    vulnerabilities_folder_path = os.path.join(config['examples-results-path'],
                                               os.path.basename(example_folder))
    vulnerabilities = reader.read_vulnerabilities(vulnerabilities_folder_path, topology.keys())

    if not vulnerabilities.keys():
        print("There is a mistake with the vulnerabilities. Terminating the function...")
        return

    # Getting the attack graph nodes and edges from the attack paths.
    # Returns a tuple of the form:
    # (attack_graph_nodes, attack_graph_edges, duration_bdf, duration_vul_preprocessing)
    att_graph_tuple = att_gr_par.generate_attack_graph(config["attack-vector-folder-path"],
                                                       config["preconditions-rules"],
                                                       config["postconditions-rules"],
                                                       topology,
                                                       vulnerabilities,
                                                       example_folder)

    print("Time elapsed: "+str(att_graph_tuple[2]+att_graph_tuple[3])+" seconds.\n")

    # Printing the graph properties.
    duration_graph_properties = att_gr_par.print_graph_properties(config["labels_edges"],
                                                                  nodes=att_graph_tuple[0],
                                                                  edges=att_graph_tuple[1])

    #print(att_graph_tuple[0])
    #print(len(att_graph_tuple[1].keys()))

    if config["show_one_vul_per_edge"]:
        for element in att_graph_tuple[1].keys():
            att_graph_tuple[1][element] = [att_graph_tuple[1][element][0]]

    # Visualizing the attack graph.
    if config['generate_graphs']:
        time_start = time.time()
        visualize_attack_graph(config["labels_edges"],
                               example_folder,
                               nodes=att_graph_tuple[0],
                               edges=att_graph_tuple[1])
        duration_visualization = time.time() - time_start
        print("Time elapsed: "+str(duration_visualization)+" seconds.\n")

    # Printing time summary of the attack graph generation.
    writer.print_summary(config["mode"],
                         config['generate_graphs'],
                         duration_topology=duration_topology,
                         duration_vulnerabilities=duration_vulnerabilities,
                         duration_bdf=att_graph_tuple[2],
                         duration_vuls_preprocessing=att_graph_tuple[3],
                         duration_graph_properties=duration_graph_properties,
                         duration_visualization=duration_visualization)

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
            main(sys.argv[1])
    else:
        print("Please have a look at the --help.")
