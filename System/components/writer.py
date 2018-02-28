#!/usr/bin/env python
"""This module is responsible for writing the outputs into files."""

import os
import json
import yaml

from components import reader

def write_topology_file(list_services, example_folder_path=""):
    """Writes list of services into a file."""

    config = reader.read_config_file()
    folder_name = os.path.basename(example_folder_path)
    topology_writing_path = os.path.join(config["examples-results-path"],
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

def write_topology_graph(example_folder_path, graph):
    """Writes the topology graph onto a dot file."""

    config = reader.read_config_file()
    folder_name = os.path.basename(example_folder_path)
    topology_graph_path = os.path.join(config["examples-results-path"],
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
