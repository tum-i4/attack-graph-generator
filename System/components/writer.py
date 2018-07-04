#!/usr/bin/env python
"""This module is responsible for writing the outputs into files."""

import os
import json
import yaml

from components import reader

def write_topology_file(list_services,
                        example_folder_path="",
                        example_result_path=""):
    """Writes list of services into a file."""

    folder_name = os.path.basename(example_folder_path)
    if example_result_path == "":
        config = reader.read_config_file()
        example_result_path = config["examples-results-path"]
    topology_writing_path = os.path.join(example_result_path,
                                         folder_name,
                                         "topology.json")

    with open(topology_writing_path, "w") as topology:
        json.dump(list_services, topology)

def write_attack_graph(example_folder_path, graph):
    """Writes the attack graph onto a dot file."""

    config = reader.read_config_file()
    folder_name = os.path.basename(example_folder_path)
    attack_graph_path = os.path.join(config["examples-results-path"],
                                     folder_name,
                                     "attack_graph.dot")
    graph.render(attack_graph_path)

def write_topology_graph(graph,
                         example_folder_path,
                         example_result_path=""):
    """Writes the topology graph onto a dot file."""

    folder_name = os.path.basename(example_folder_path)
    if example_result_path == "":
        config = reader.read_config_file()
        example_result_path = config["examples-results-path"]
    topology_graph_path = os.path.join(example_result_path,
                                       folder_name,
                                       "topology_graph.dot")
    graph.render(topology_graph_path)

def write_clarictl_config_file(clairctl_home, clairctl_config_dict):
    """Writes the modified clairctl config file."""

    with open(os.path.join(clairctl_home, "clairctl.yml"), "w") as outfile:
        yaml.dump(clairctl_config_dict, outfile)

def copy_vulnerability_file(clairctl_home, image_name, old_root_path, parent_folder):
    """Copies the vulnerability file from clairctl to the local location."""

    config = reader.read_config_file(old_root_path)
    parent_folder = os.path.basename(parent_folder)

    os.rename(os.path.join(clairctl_home,
                           "docker-compose-data",
                           "clairctl-reports",
                           "json",
                           "analysis-"+image_name+"-latest.json"),
              os.path.join(old_root_path,
                           config["examples-results-path"],
                           parent_folder,
                           image_name+"-vulnerabilities.json"))

def create_folder(example_folder_path):
    """Creates folder for storing the intermediate results of the examples."""

    config = reader.read_config_file()
    directory_path = os.path.join(config["examples-results-path"], example_folder_path)
    if not os.path.exists(directory_path):
        os.makedirs(directory_path, mode=0o777)

def print_summary(config_mode,
                  config_generate_graphs,
                  no_topology_nodes=0,
                  no_topology_edges=0,
                  no_attack_graph_nodes=0,
                  no_attack_graph_edges=0,
                  duration_topology=0,
                  duration_vulnerabilities=0,
                  duration_vuls_preprocessing=0,
                  duration_bdf=0,
                  duration_graph_properties=0,
                  duration_visualization=0,
                  duration_total_time=0):
    """Function responsible for printing the time and properties summary."""

    if no_topology_nodes != 0 and \
       no_topology_edges != 0 and \
       no_attack_graph_nodes != 0 and \
       no_attack_graph_edges != 0:
        print("\n**********Nodes and edges summary of the topology and attack graphs**********")

    if no_topology_nodes != 0:
        print("The number of nodes in the topology graph is "+str(no_topology_nodes)+".")

    if no_topology_edges != 0:
        print("The number of edges in the topology graph is "+str(no_topology_edges)+".")

    if no_attack_graph_nodes != 0:
        print("The number of nodes in the attack graph is "+str(no_attack_graph_nodes)+".")

    if no_attack_graph_edges != 0:
        print("The number of edges in the attack graph is "+str(no_attack_graph_edges)+".")

    print("\n**********Time Summary of the Attack Graph Generation Process**********")

    print("Topology parsing took "+str(duration_topology)+" seconds.")

    if config_mode == "online":
        print("Vulnerability parsing took "+str(duration_vulnerabilities)+" seconds.")

    print("The attack graph generation took " + \
          str(duration_vuls_preprocessing+duration_bdf)+" seconds.")

    print("	-Preprocessing of the vulnerabilities took " + \
          str(duration_vuls_preprocessing)+" seconds.")

    print("	-Breadth First Search took "+str(duration_bdf)+" seconds.")

    if duration_graph_properties != 0:
        print("Calculation of Graph Properties took "+str(duration_graph_properties)+" seconds.")

    if config_generate_graphs:
        print("Attack Graph Visualization took "+str(duration_visualization)+" seconds.")

    if duration_total_time != 0:
        print("The total elapsed time is "+str(duration_total_time)+" seconds.")
    print("\n\n")
