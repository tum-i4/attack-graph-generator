#!/usr/bin/env python
"""Module responsible for generating the attack graph."""

import json
import os
from queue import Queue
import time

from components import reader
from components import topology_parser as top_par

def get_exploitable_vul(container,
                        cleaned_vulnerabilities,
                        attack_vector_dict,
                        attack_filter):
    """Filtering out only the vulnerabilities that could be exploited."""

    # Here are we going to store the exploitable vulnerabilities.
    vulnerability_exploitable = []

    # Get the vulnerabilities that filfill the criteria.
    for vulnerability in cleaned_vulnerabilities:

        # We check if the vulnerabilities are in the attack vector dictionary.
        if vulnerability in attack_vector_dict:
            attack_vec = attack_vector_dict[vulnerability]

            # Checking which vulnerabilites fulfill our criteria.
            if attack_vec["integrityImpact"] == attack_filter["integrityImpact"] and \
               attack_vec["confidentialityImpact"] == attack_filter["confidentialityImpact"] and \
               attack_vec["authentication"] == attack_filter["authentication"] and \
               attack_vec["accessVector"] == attack_filter["accessVector"] and \
               attack_vec["accessComplexity"] == attack_filter["accessComplexity"]:
                vulnerability_exploitable.append(vulnerability)

    print("Total "+ str(len(vulnerability_exploitable))
                  + " exploitable vulnerabilities in countainer "
                  + container+".")
    return vulnerability_exploitable

def clean_vulnerabilities(raw_vulnerabilities, container):
    """Cleans the vulnerabilities for a given container."""

    print("Getting the vurnabilities")

    vulnerabilities = []

    # Going to the .json hierarchy to get the CVE ids.
    layers = raw_vulnerabilities["Layers"]
    for layer in layers:
        features = layer["Layer"]["Features"]
        for feature in features:
            if "Vulnerabilities" in feature:
                vulnerabilities_structure = feature["Vulnerabilities"]
                for vulnerability in vulnerabilities_structure:
                    if vulnerability["Name"] not in vulnerabilities:
                        vulnerabilities.append(vulnerability["Name"])

    print("Total " + str(len(vulnerabilities))
                   + " vulnerabilities in container "+container+".")

    return vulnerabilities

def get_graph(attack_paths):
    """Getting the nodes and edges for an array of attack paths."""

    # Initializing the nodes and edges arrays.
    nodes = []
    edges = {}

    # Generating unique nodes.
    for attack_path in attack_paths:
        for node in attack_path:
            if node not in nodes:
                nodes.append(node)

    # Generating unique edges.
    for attack_path in attack_paths:

        # Checking if an edge is present.
        if len(attack_path) >= 2:
            for i in range(1, len(attack_path)):
                key = attack_path[i]+"|"+attack_path[i-1]
                edges[key] = [attack_path[i], attack_path[i-1]]

    return nodes, edges

def get_attack_vector(attack_vector_files):
    """Merging the attack vector files into a dictionary."""

    # Initializing the attack vector dictionary.
    attack_vector_dict = {}

    # Iterating through the attack vector files.
    for attack_vector_file in attack_vector_files:

        # Load the attack vector.
        cve_items = attack_vector_file["CVE_Items"]

        # Filtering only the important information and creating the dictionary.
        for cve_item in cve_items:
            if "baseMetricV2" in cve_item["impact"]:
                cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
                cve_attack_vector = cve_item["impact"]["baseMetricV2"]["cvssV2"]
                attack_vector_dict[cve_id] = cve_attack_vector

    return attack_vector_dict

def breadth_first_search(goal_container,
                         topology,
                         container_exploitability):
    """Breadth first search approach for generation of attack paths."""

    # This is where the attack paths are going to be stored.
    attack_paths = []

    # This is where the backtracking breadth-first-search starts.
    # Starts from the goal container and its vulnerabilities.
    queue = Queue()
    for vulnerability_exploitable in container_exploitability[goal_container]:
        key = goal_container+"("+vulnerability_exploitable+")"
        queue.put({"node_id": key, "path": []})

    bds_start =time.time()

    # Iterate while the queue is not empty.
    while not queue.empty():
        node = queue.get()

        # Get the neighbours for the node.
        neighbours = topology[node["node_id"].split("(")[0]]

        # For every neighbour of the node:
        for neighbour in neighbours:

            # Checks if the outside network is reached.
            if neighbour == "outside":
                node["path"].append(node["node_id"])
                node["path"].append("outside")
                attack_paths.append(node["path"])
                continue
            else:
                # Checks if the node is already passed and ensures monotonicity.
                already_passed = False
                for passed_node in node["path"]:
                    if passed_node.startswith(neighbour):
                        already_passed = True

                # If the node is not passed, add it to the queue with the respective vulnerability.
                if not already_passed:
                    for vulnerability_exploitable in container_exploitability[neighbour]:
                        key = neighbour+"("+vulnerability_exploitable+")"

                        queue.put({"node_id": key, "path": node["path"] + [node["node_id"]]})

    print("Breadth-first-search took "+str(time.time()-bds_start)+" seconds.")
    return attack_paths

def breadth_first_search_direct(goal_container,
                         topology,
                         container_exploitability):
    """Breadth first search approach for generation of nodes and edges without generating attack paths.

    This way scales more than the previous one in terms of memory requirements."""

    # This is where the nodes and edges are going to be stored.
    edges = {}
    nodes = []
    passed_nodes = {}

    # Creating the nodes.
    for container in topology:
        if container != "outside":
            exploitable_vulnerabilities = container_exploitability[container]
            for vulnerability in exploitable_vulnerabilities:
                node = container+"("+vulnerability+")"
                nodes.append(node)
        passed_nodes[container] = False

    # Creating the edges.
    # This is where the backtracking breadth-first-search starts.
    # Starts from the goal container and its vulnerabilities.
    bds_start =time.time()

    # Initiaizing the queue.
    queue = Queue()
    queue.put(goal_container)

    # Iterate while the queue is not empty.
    while not queue.empty():
        ending_node = queue.get()
        passed_nodes[ending_node] = True
        cont_exp_end = container_exploitability[ending_node]
        
        # Get the neighbours for the node.
        neighbours = topology[ending_node]

        # For every neighbour of the node:
        for neighbour in neighbours:

            # Checks if the outside network is reached.
            if neighbour == "outside":
                for vulnerability_exploitable_end in cont_exp_end:
                    node_end = ending_node+"("+vulnerability_exploitable_end+")"
                    key = "outside"+"|"+ node_end
                    edges[key] = ["outside", node_end]
                continue
            
            # Checks if the node is already passed and ensures monotonicity.
            if not passed_nodes[neighbour]:
                queue.put(neighbour)

            # Goal container should have only incoming edges.
            if neighbour == goal_container:
                continue

            # If the node is not passed, add it to the queue with the respective vulnerability.
            for vulnerability_exploitable_start in container_exploitability[neighbour]:
                for vulnerability_exploitable_end in cont_exp_end:
                    node_start = neighbour+"("+vulnerability_exploitable_start+")"
                    node_end = ending_node+"("+vulnerability_exploitable_end+")"
                    key = node_start+"|"+node_end
                    edges[key] = [node_start, node_end]

    duration_bdf = time.time()-bds_start
    print("Breadth-first-search took "+str(duration_bdf)+" seconds.")
    return nodes, edges, duration_bdf

def generate_attack_graph(goal_container_name,
                          example_folder,
                          attack_vector_path,
                          attack_filter):
    """Main pipeline for the attack graph generation algorithm."""

    print("Start with attack graph generation...")

    # Read the topology.
    topology = reader.read_topology(example_folder)

    # Read the attack vector files.
    attack_vector_files = reader.read_attack_vector_files(attack_vector_path)

    # Read the service to image mapping.
    mapping_names = top_par.get_mapping_service_to_image_names(example_folder)
    
    # Merging the attack vector files and creating an attack vector dictionary.
    attack_vector_dict = get_attack_vector(attack_vector_files)

    # Getting the potentially exploitable vulnerabilities for each container.
    container_exploitability = {}
    for container_name in topology.keys():
        if container_name != "outside":

            # Reading the vulnerability
            vulnerabilities = reader.read_vulnerabilities(example_folder, container_name)
            
            # Remove junk and just takethe most important part from each vulnerability
            cleaned_vulnerabilities = clean_vulnerabilities(vulnerabilities, container_name)

            # Get exploitable vulnerabilities based on attack vector.
            container_exploitability[container_name] = get_exploitable_vul(container_name,
                                                                      cleaned_vulnerabilities,
                                                                      attack_vector_dict,
                                                                      attack_filter)

    # Breadth first search algorithm for generation of attack paths.
    nodes, edges, duration_bdf = breadth_first_search_direct(mapping_names[goal_container_name],
                                        topology,
                                        container_exploitability)

    print("Attack graph generation finished.")

    # Returns a graph with nodes and edges.
    #return get_graph(attack_paths)
    return nodes, edges, duration_bdf
