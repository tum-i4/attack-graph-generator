#!/usr/bin/env python
"""Main module responsible for the attack graph generation pipeline."""

import sys
import os
import time
import networkx as nx

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

def print_graph_properties(nodes, edges):
    """This functions prints graph properties."""

    print("\n**********Attack Graph properties**********")
    # Create the graph
    graph = nx.DiGraph()
    for node in nodes:
        graph.add_node(node)
    for edge in edges:
        graph.add_edge(edges[edge][0], edges[edge][1], contstraint='false')

    # Calculate the attack graph properties
    
    # Number of nodes
    no_nodes = graph.number_of_nodes()
    print("The number of nodes in the graph is "+str(no_nodes))

    # Number of edges
    no_edges = graph.number_of_edges()
    print("The number of edges in the graph is "+str(no_edges))

    # Degree centrality
    degree_centrality = nx.degree_centrality(graph)
    print("The degree centrality of the graph is "+str(degree_centrality))

    # Average degree centrality
    avg_degree_centrality = 0
    for node in degree_centrality:
        avg_degree_centrality = avg_degree_centrality + degree_centrality[node]
    if no_nodes != 0:
        avg_degree_centrality = avg_degree_centrality / no_nodes
    print("The average degree centrality of the graph is "+str(avg_degree_centrality))
    #sum_centrality = 0
    #for node in property_graph:
    #    sum_centrality = sum_centrality + property_graph[node]
    #print("The average degree centrality of the graph is "+str(sum_centrality/len(property_graph)))
    """ -- they dont work for directed graphs
    # Radius 
    property_graph = nx.radius(graph)
    print("The radius of the graph is "+str(property_graph))
    
    # Diameter   
    property_graph = nx.diameter(graph)
    print("The radius of the graph is "+str(property_graph))
    """
    
    # Connectivity
    """
    property_graph = nx.average_degree_connectivity(graph)
    print("The average degree conectivity of the graph is "+str(property_graph))

    property_graph = nx.degree_assortativity_coefficient(graph)
    print("The average degree assortativity coefficient of the graph is "+str(property_graph))
    """

    # In-degree and average in-degree
    in_degree = graph.in_degree()
    print("The in-degree is "+str(in_degree))

    avg_in_degree = 0
    for node in in_degree:
        avg_in_degree = avg_in_degree + node[1]
    if no_nodes != 0:
        avg_in_degree = avg_in_degree / no_nodes
    print("The average in-degree is "+str(avg_in_degree))

    out_degree = graph.out_degree()
    print("The out-degree is "+str(out_degree))

    avg_out_degree = 0
    for node in out_degree:
        avg_out_degree = avg_out_degree + node[1]
    if no_nodes != 0:
        avg_out_degree = avg_out_degree / no_nodes
    print("The average out-degree is "+str(avg_out_degree))


    print("Is the graph strongly connected? "+str(nx.is_strongly_connected(graph)))

    """
    # Cycles
    cycle_basis(graph)

    # Betweenness

    # Clustering

    # Closeness

    # Eccentriity
    eccentricity(graph)

    # Cliques

    # N- cliques

    # Principal eigenvector
    eigenvector_centrality(graph)

    # Redundancy

    # Dispersion"""

def main(example_folder, goal_container):
    """Main function responsible for running the attack graph generation pipeline."""

    # Opening the configuration file.
    config = reader.read_config_file()

    # Create folder where the result files will be stored.
    writer.create_folder(os.path.basename(example_folder))

    # Parsing the topology of the docker containers.
    time_start = time.time()
    top_par.parse_topology(example_folder)
    duration_topology = time.time() - time_start
    print("Time elapsed: "+str(duration_topology)+" seconds.\n")

    # Parsing the vulnerabilities for each docker container.
    if config["mode"] == "online":
        time_start = time.time()
        vul_par.parse_vulnerabilities(example_folder)
        duration_vulnerabilities = time.time() - time_start
        print("Time elapsed: "+str(duration_vulnerabilities)+" seconds.\n")

    # Getting the attack graph nodes and edges from the attack paths.
    time_start = time.time()
    nodes, edges, duration_bdf = att_gr_par.generate_attack_graph(goal_container,
                                                                  example_folder,
                                                                  config["attack-vector-folder-path"],
                                                                  config["attack-vector-filter"])
    duration_attack_graph = time.time() - time_start
    print("Time elapsed: "+str(duration_attack_graph)+" seconds.\n")

    # Printing the graph properties.
    time_start = time.time()
    print_graph_properties(nodes, edges)
    duration_graph_properties = time.time() - time_start
    print("Time elapsed: "+str(duration_graph_properties)+" seconds.\n")
    
    # Visualizing the attack graph.
    time_start = time.time()
    visualize_attack_graph(example_folder, nodes, edges)
    duration_visualization = time.time() - time_start
    print("Time elapsed: "+str(duration_visualization)+" seconds.\n")

    # Printing time summary of the attack graph generation.
    print("\n**********Time Summary of the Attack Graph Generation Process**********")
    print("Topology parsing took "+str(duration_topology)+" seconds.")
    print("Vulnerability parsing took "+str(duration_vulnerabilities)+" seconds.")
    print("Attack Graph Generation took "+str(duration_attack_graph)+" seconds.")
    print("    -Breadth First Search took "+str(duration_bdf)+" seconds.")
    print("Calculation of Graph Properties took "+str(duration_graph_properties)+" seconds.")
    print("Attack Graph Visualization took "+str(duration_visualization)+" seconds.")
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
